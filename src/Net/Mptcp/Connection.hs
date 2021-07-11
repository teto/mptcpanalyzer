{-# LANGUAGE OverloadedStrings #-}
module Net.Mptcp.Connection (
  MptcpConnection(..)
  , MptcpSubflow(..)
  , showMptcpConnectionText
)
where
import Net.IP
import Net.Tcp
-- import MptcpAnalyzer.Arti
import Data.Word (Word8, Word16, Word32, Word64)
import Data.Text as TS
import qualified Data.Set as Set
import MptcpAnalyzer.Stream
import MptcpAnalyzer.ArtificialFields


{- Holds all necessary information about a multipath TCP connection
-}
data MptcpConnection = MptcpConnection {
  -- todo prefix as mpcon
  mptcpStreamId :: StreamIdMptcp
  , mptcpServerKey :: Word64    -- ^ MPTCP server key
  , mptcpClientKey :: Word64    -- ^ MPTCP client key
  , mptcpServerToken :: Word32  -- ^ Hash of the server key
  , mptcpClientToken :: Word32
  , mptcpNegotiatedVersion :: Word8  -- ^ 0 or 1 at least for now
  -- should be a subflow
  , mpconSubflows :: Set.Set MptcpSubflow  -- ^ List of all subflows seen during communication

-- Ord to be able to use fromList
} deriving (Show, Eq, Ord)

-- | Extension of @TcpConnection@
-- master subflow has implicit addrid 0
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
    tpl = "Server key/token: " <> tshow (mptcpServerKey con) <> "/" <> tshow ( mptcpServerToken con)
        <> "\nClient key/token: " <> tshow (mptcpClientKey con) <> "/" <> tshow ( mptcpClientToken con)
