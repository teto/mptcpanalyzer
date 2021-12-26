{-# LANGUAGE OverloadedStrings #-}
module Net.Tcp.ConnectionSpec (spec)
where


import Test.Hspec
import Net.IP
import Net.IPv4 (localhost)
import Net.Tcp.Connection
import Net.Stream
import Data.Maybe (fromJust)

exampleTcpTuple0 :: TcpConnectionOriented
exampleTcpTuple0 = TcpConnectionOriented (fromJust $ decode "10.0.0.1") (fromJust $ decode "192.10.0.2") 24 42

exampleTcpConnection0rev :: TcpConnectionOriented
exampleTcpConnection0rev = TcpConnectionOriented (fromJust $ decode "192.10.0.2") (fromJust $ decode "10.0.0.1") 42 24

exampleTcpConnection0 :: TcpConnection
exampleTcpConnection0 = TcpConnection (fromJust $ decode "10.0.0.1") (fromJust $ decode "192.10.0.2") 24 42 (StreamId 0)

spec :: Spec
spec = 
  describe "connection tests" $ do
    it "Check reversing of connection" $
      reverseTcpConnectionTuple exampleTcpTuple0 `shouldBe` exampleTcpConnection0rev
    it "Check conversion of tuple into connection" $
      tcpConnectionFromOriented exampleTcpTuple0 `shouldBe` exampleTcpConnection0

