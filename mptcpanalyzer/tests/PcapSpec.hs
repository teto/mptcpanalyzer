module Main where
-- import           Test.Tasty
-- import           Test.Tasty.HUnit
import Distribution.Simple.Utils (TempFileOptions(..), withTempFileEx)
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import Net.IP
import Net.IPv4 (localhost)
import Net.Tcp.Connection
import System.Exit (ExitCode(ExitSuccess))
import System.IO
import Test.Hspec
import Test.QuickCheck hiding (Success)
import Tshark.Main



exampleTcpConnection :: TcpConnection
exampleTcpConnection = TcpConnection (fromIPv4 localhost) (fromIPv4 localhost) 24 42 (StreamId 0)

opts :: TempFileOptions
opts = TempFileOptions True

main :: IO ()
main = hspec $ do
  describe "absolute" $ do
    it "Generate the correct tshark filter" $
      genReadFilterFromTcpConnection exampleTcpConnection Nothing
        `shouldBe` "tcp and ip.addr==127.0.0.1 and ip.addr==127.0.0.1 and tcp.port==42 and tcp.port==24"
      -- exportToCsv "mptcpanalyzer/examples/client_2_filtered.pcapng"
    it "Tshark generates a proper CSV file" $ do
      -- cant find the profile so there is some herr being written
      withFile "/tmp/mptcp.csv" ReadWriteMode (exportToCsv defaultTsharkPrefs "examples/client_2_filtered.pcapng") >>= \x -> fst x `shouldBe` ( ExitSuccess)

      -- `shouldThrow`
    it "Test frame loading" $
      pendingWith "test"
