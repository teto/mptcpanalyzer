{-|
Module      : Net.Tcp.Definitions
Description : Implementation of mptcp netlink path manager
Maintainer  : matt
Stability   : testing
Portability : Linux

-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveAnyClass #-}
-- module Net.Tcp.Definitions (
--       TcpConnection (..)
--     , ConnectionRole (..)
--     , reverseTcpConnection
--     , showTcpConnection
-- )

-- where

-- import Data.Aeson
-- import qualified Data.Text as TS
-- import Data.Word (Word16, Word32, Word8)
-- import GHC.Generics
-- import Net.IP
-- import Prelude

-- {- Describe a TCP connection, possibly an Mptcp subflow
--   The equality implementation ignores several fields
-- -}
-- data TcpConnection = TcpConnection {
--   -- TODO use libraries to deal with that ? filter from the command line for instance ?
--     srcIp            :: IP -- ^Source ip
--   , dstIp            :: IP -- ^Destination ip
--   , srcPort          :: Word16  -- ^ Source port
--   , dstPort          :: Word16  -- ^Destination port
--   , priority         :: Maybe Word8 -- ^subflow priority
--   , localId          :: Word8  -- ^ Convert to AddressFamily
--   , remoteId         :: Word8
--   -- TODO remove could be deduced from srcIp / dstIp ?
--   , subflowInterface :: Maybe Word32 -- ^Interface of Maybe ? why a maybe ?
--   -- add TcpMetrics member
--   -- , tcpMetrics :: Maybe [SockDiagExtension]  -- ^Metrics retrieved from kernel

-- } deriving (Show, Generic, Ord, FromJSON, ToJSON)

-- tshow :: Show a => a -> TS.Text
-- tshow = TS.pack . Prelude.show

-- data ConnectionRole = Server | Client deriving (Show, Eq)


-- showTcpConnectionText :: TcpConnection -> TS.Text
-- showTcpConnectionText con =
--   showIp ( srcIp con) <> ":" <> tshow (srcPort con) <> " -> " <> showIp (dstIp con) <> ":" <> tshow (dstPort con)
--   where
--     showIp = Net.IP.encode

-- showTcpConnection :: TcpConnection -> String
-- showTcpConnection = TS.unpack . showTcpConnectionText


-- reverseTcpConnection :: TcpConnection -> TcpConnection
-- reverseTcpConnection con = con {
--     srcIp = dstIp con
--   , dstIp = srcIp con
--   , srcPort = dstPort con
--   , dstPort = srcPort con
--   , priority = Nothing
--   , localId = remoteId con
--   , remoteId = localId con
--   , subflowInterface = Nothing
-- }

-- -- TODO create a specific function for it
-- -- ignore the rest
-- instance Eq TcpConnection where
--   x == y = srcIp x == srcIp y && dstIp x == dstIp y
--             && srcPort x == srcPort y && dstPort x == dstPort y


