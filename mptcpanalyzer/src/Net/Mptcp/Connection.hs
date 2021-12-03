{-|
Module      : Net.Mptcp.Connection
Description : Basic MPTCP connection description
Maintainer  : matt
License     : GPL-3
-}
{-# LANGUAGE OverloadedStrings #-}
module Net.Mptcp.Connection (
  -- * Types
  MptcpConnection(..)
  , MptcpSubflow(..)
  , showMptcpConnectionText
)
where
import Net.IP
import Net.Tcp
-- import MptcpAnalyzer.Arti
import qualified Data.Set as Set
import Data.Text as TS
import Data.Word (Word16, Word32, Word64, Word8)
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Stream


-- | Holds all necessary information about a multipath TCP connection
data MptcpConnection = MptcpConnection {
  -- todo prefix as mpcon
  -- |The wireshark mptcp.stream identifier (a number)
  mptcpStreamId :: StreamIdMptcp
  -- |Server key exchanged during the handshake
  , mptcpServerKey :: Word64
  -- |Client key exchanged during the handshake
  , mptcpClientKey :: Word64
  -- |Hash of the server key
  , mptcpServerToken :: Word32
  , mptcpClientToken :: Word32
  -- | Mptcp version negotiated during the handshake Not implemented yet ?
  , mptcpNegotiatedVersion :: Word8  -- ^ 0 or 1 at least for now
  -- ^ List of past/present/future subflows seen during communication
  , mpconSubflows :: Set.Set MptcpSubflow

-- Ord to be able to use fromList
} deriving (Show, Eq, Ord)

-- | Extension of @TcpConnection@
-- master subflow has implicit addrid 0
-- TODO add start/end dates ?
data MptcpSubflow = MptcpSubflow {
      sfConn :: TcpConnection
      -- shall keep token instead ? or as a boolean ?
      -- Todo token
      -- , sfMptcpDest :: ConnectionRole -- ^ Destination
      , sfJoinToken :: Maybe Word32 -- ^ token of sendkey to authentify itself, Nothing -> Master subflow
      , sfPriority :: Maybe Word8 -- ^subflow priority
      , sfLocalId :: Word8  -- ^ Convert to AddressFamily
      , sfRemoteId :: Word8
      --conTcp TODO remove could be deduced from srcIp / dstIp ?
      , sfInterface :: Text -- ^Interface of Maybe ? why a maybe ?
    } deriving (Show, Eq, Ord)

tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show

-- |Pretty print an MPTCP connection
showMptcpConnectionText :: MptcpConnection -> Text
showMptcpConnectionText con =
  -- showIp (srcIp con) <> ":" <> tshow (srcPort con) <> " -> " <> showIp (dstIp con) <> ":" <> tshow (dstPort con)
  tpl <> "\n" <> TS.unlines (Prelude.map (showTcpConnectionText . sfConn) (Set.toList $ mpconSubflows con))
  where
    -- todo show version
    tpl :: Text
    tpl = TS.unlines [
      "Server key/token: " <> tshow (mptcpServerKey con) <> "/" <> tshow ( mptcpServerToken con)
      , "Client key/token: " <> tshow (mptcpClientKey con) <> "/" <> tshow ( mptcpClientToken con)
      ]
