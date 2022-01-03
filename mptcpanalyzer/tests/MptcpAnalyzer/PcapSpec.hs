{-# LANGUAGE OverloadedStrings #-}
module MptcpAnalyzer.PcapSpec (
spec
) where
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import Net.IP
import Net.IPv4 (localhost)
import Net.Tcp.Connection
import Test.Hspec
import Data.Maybe (fromJust)
import MptcpAnalyzer.ArtificialFields
import Utils
import qualified Data.Foldable as F
import MptcpAnalyzer.Types
import Distribution.Compat.Lens (view)
-- import Control.Lens


exampleTcpConnectionLocalhost :: TcpConnection
exampleTcpConnectionLocalhost = TcpConnection (fromIPv4 localhost) (fromIPv4 localhost) 24 42 (StreamId 0)

exampleTcpConnection0 :: TcpConnection
exampleTcpConnection0 = TcpConnection (fromJust $ decode "10.0.0.1") (fromJust $ decode "192.10.0.2") 24 42 (StreamId 1)


-- addTcpDestinationsToAFrame
-- genTcpDestFrame

spec :: Spec
spec = describe "absolute" $ do
  it "Check TcpConnection score" $
    scoreTcpCon exampleTcpConnectionLocalhost exampleTcpConnection0 < scoreTcpCon exampleTcpConnectionLocalhost exampleTcpConnectionLocalhost
  before (loadAFrame "examples/client_2_cleaned.pcapng" (StreamId 0)) $ it "Check that destinations are set correctly" $ \aframe ->
    length (genTcpDestFrameFromAFrame aframe) == (length $ ffFrame aframe)
  before (loadAFrame "examples/client_2_cleaned.pcapng" (StreamId 0)) $ it "Check that destinations are set correctly" $ \aframe ->
    let
      tcpdestFrame = genTcpDestFrameFromAFrame aframe
      tcpDests = F.toList $ view tcpDest <$> tcpdestFrame
      -- clientFrame = filterFrame (\x -> x ^. tcpDest == RoleClient) tcpdestFrame
    in
      length (filter ((==) RoleServer) tcpDests) `shouldBe` 16
      -- length (ffFrame aframe) `shouldBe` (length $ clientFrame)
    -- it "Generate the correct tshark filter" $
--       genReadFilterFromTcpConnection exampleTcpConnection0 (Just RoleClient)
--         `shouldBe` "tcp and ip.addr==127.0.0.1 and ip.addr==127.0.0.1 and tcp.srcport==42 and tcp.dstport==24"
--       -- exportToCsv "mptcpanalyzer/examples/client_2_filtered.pcapng"
--     it "Tshark generates a proper CSV file" $ do
--       -- cant find the profile so there is some herr being written
--       withFile "/tmp/mptcp.csv" ReadWriteMode (exportToCsv defaultTsharkPrefs "examples/client_2_filtered.pcapng") >>= \x -> fst x `shouldBe` ( ExitSuccess)
--       -- `shouldThrow`
--     it "Test frame loading" $
--       pendingWith "test"
