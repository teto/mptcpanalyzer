module Net.Mptcp.ConnectionSpec (spec)
where

import Test.Hspec
import Net.IP
import Net.Stream
import Net.IPv4 (localhost)
import Net.Mptcp.Connection

example0 :: MptcpConnection
example0 = MptcpConnection {
    mpconStreamId = StreamId 0
  , serverConfig = MptcpEndpointConfiguration 1 32 0
  , clientConfig = MptcpEndpointConfiguration 4 65 0
  , subflows = mempty
  }


-- TcpConnectionOriented (fromJust $ decode "10.0.0.1") (fromJust $ decode "192.10.0.2") 24 42

-- exampleTcpConnection0rev :: TcpConnectionOriented
-- exampleTcpConnection0rev = TcpConnectionOriented (fromJust $ decode "192.10.0.2") (fromJust $ decode "10.0.0.1") 42 24

-- exampleTcpConnection0 :: TcpConnection
-- exampleTcpConnection0 = TcpConnectionOriented (fromJust $ decode "10.0.0.1") (fromJust $ decode "192.10.0.2") 24 42 (StreamId 0)

spec :: Spec
spec =
  describe "connection tests" $ do
    -- TODO check getMasterSubflow tokenBelongToConnection (a renommer)
    it "Check reversing of connection" $
      True `shouldBe` True
      -- reverseTcpConnection exampleTcpTuple0 `shouldBe` exampleTcpConnection0rev
    -- it "Check conversion of tuple into connection" $
      -- tcpConnectionFromOriented exampleTcpTuple0 `shouldBe` exampleTcpConnection0


