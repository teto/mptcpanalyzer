module Main where
-- import           Test.Tasty
-- import           Test.Tasty.HUnit
import           Test.Hspec
import           Test.QuickCheck                    hiding (Success)
import           MptcpAnalyzer.Pcap
import           Tshark.Main
import           Net.Tcp.Connection
import           Net.IP
import Net.IPv4 (localhost)
import MptcpAnalyzer.Stream



exampleTcpConnection :: TcpConnection
exampleTcpConnection = TcpConnection (fromIPv4 localhost) (fromIPv4 localhost) 24 42 (StreamId 0)

main :: IO ()
main = hspec $ do
  describe "absolute" $ do
    it "Generate the correct tshark filter" $
      genReadFilterFromTcpConnection exampleTcpConnection Nothing `shouldBe` "tcp and ip.addr==127.0.0.1 and ip.addr==127.0.0.1 and tcp.port==42 and tcp.port==24"
