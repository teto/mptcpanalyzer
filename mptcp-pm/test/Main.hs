{-# LANGUAGE OverloadedStrings #-}
{-|
https://stackoverflow.com/questions/32913552/why-does-my-hunit-test-suite-pass-when-my-tests-fail
-}
module Main where

import Net.Bitset
import Net.IP
import Net.Mptcp
import Net.SockDiag
import Net.Tcp
import Net.Bitset
import Net.Mptcp
import Net.Stream
import Net.Tcp.Constants
import System.Exit
import Test.HUnit

import Data.Text (Text)
import qualified Data.Text as T
import Net.IPv4 (localhost)
import Numeric (readHex)

-- TODO reestablish this
testEmpty = TestCase $ assertEqual
  "Check"
  1
  ( enumsToWord [TcpEstablished] )

testCombo = TestCase $ assertEqual
  "Check"
  513
  ( enumsToWord [TcpEstablished, TcpListen] )

testComboReverse = TestCase $ assertEqual
  "Check"
  513
  ( enumsToWord [TcpEstablished, TcpListen] )

iperfConnection = let 
    con =  TcpConnection {
          clientIp = (fromIPv4 localhost)
        , serverIp = fromIPv4 localhost
        , conclientPort = 5000
        , serverPort = 1000
        , streamId = (StreamId 0)
      }
  in MptcpSubflow {
          connection = con
        -- placeholder values
        , joinToken = Just 0
        , priority = Nothing
        , interface = Nothing
        , localId = 0
        , remoteId = 0
    }

modifiedConnection = iperfConnection { interface = Just 0 }

filteredConnections :: [MptcpSubflow]
filteredConnections = [ iperfConnection ]


connectionFilter = TestCase $ assertBool
  "Check connection is in the list"
  (iperfConnection `elem` filteredConnections)



instance ToBitMask TcpFlag

-- check we can read an hex from tshark
-- 0x00000012
--  returns a list of possible parses as (a,String) pairs.
loadTcpFlagsFromHex :: Text -> [TcpFlag]
loadTcpFlagsFromHex text = case readHex (T.unpack $ T.drop 2 text) of
  [(n, "")] -> fromBitMask n
  _         -> error $ "TcpFlags: could not parse " ++ T.unpack text


-- connectionFilter = TestCase $ assertEqual
--   "Check connection is in the list"
--   True
--   ( iperfConnection `elem` filteredConnections)

-- main :: IO Count
main = do

  results <- runTestTT $ TestList [
      TestLabel "subflow is correctly filtered" connectionFilter
      , TestCase $ assertBool "connection should be equal" (iperfConnection == iperfConnection)
      -- , TestCase $ assertEqual "connection should be equal despite different interfaces"
      --     iperfConnection modifiedConnection
      -- TODO restore
      -- , TestCase $ assertBool "connection should be considered as in list"
      --     (modifiedConnection `elem` filteredConnections)
      -- , TestCase $ assertBool "connection should not be considered as in list"
      --     (modifiedConnection `notElem` filteredConnections)
      , TestList [
        TestCase $ assertEqual "to bitset " 2 (toBitMask [TcpFlagSyn])
        , TestCase $ assertEqual "Check tcp syn flags" [TcpFlagSyn]
          (loadTcpFlagsFromHex "0x00000002")
        , TestCase $ assertEqual "Check tcp syn/ack flags" [TcpFlagSyn, TcpFlagAck]
          (loadTcpFlagsFromHex "0x00000012")
      ]
    ]
  if errors results + failures results == 0 then
      exitSuccess
    else
      exitWith (ExitFailure 1)
