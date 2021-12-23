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
  , MptcpEndpointConfiguration(..)
  , showMptcpConnectionText

  , mptcpConnAddSubflow
  , getMasterSubflow
)
where
import Net.IP
import Net.Tcp
-- import MptcpAnalyzer.Arti
import qualified Data.Set as Set
import Data.Text as TS
import Data.Word (Word16, Word32, Word64, Word8)
-- import MptcpAnalyzer.ArtificialFields
import Net.Stream

data MptcpEndpointConfiguration = MptcpEndpointConfiguration {
  -- |key exchanged during the handshake
    mecKey :: Word64
  , mecToken :: Word32
  -- ^Hash of the server key
  , mecVersion :: Int -- ^ 0 or 1 at least for now
  -- , mecIdsn :: Word64
  -- ^ Initial data sequence number
  } deriving (Show, Eq)

-- | Holds all necessary information about a multipath TCP connection
-- TODO add an imcomplete constructor ?
data MptcpConnection = MptcpConnection {
  -- todo prefix as mpcon
  -- |The wireshark mptcp.stream identifier (a number)
    mptcpStreamId :: StreamIdMptcp
  -- |Server key exchanged during the handshake
  , mptcpServerConfig :: MptcpEndpointConfiguration
  , mptcpClientConfig :: MptcpEndpointConfiguration
  -- | Mptcp version negotiated during the handshake Not implemented yet ?
  -- , mptcpNegotiatedVersion :: Word8  -- ^ 0 or 1 at least for now
  -- ^ List of past/present/future subflows seen during communication
  , mpconSubflows :: Set.Set MptcpSubflow

-- Ord to be able to use fromList
} deriving (Show, Eq)

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
      -- allow 
      , sfInterface :: Maybe Word32 -- ^Interface of Maybe ? why a maybe ?
      -- Maybe Word32 -- ^Interface of Maybe ? why a maybe ?
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
      "Server key/token: " <> tshow ((mecKey . mptcpServerConfig) con) <> "/" <> ((tshow . mecToken . mptcpServerConfig) con)
      , "Client key/token: " <> tshow ((mecKey . mptcpClientConfig) con) <> "/" <> ((tshow . mecToken . mptcpClientConfig) con)
      ]

---- add a maybe ?
getMasterSubflow :: MptcpConnection -> Maybe MptcpSubflow
getMasterSubflow mptcpCon = case Prelude.filter (\sf -> sfLocalId sf == 0) (Set.toList $ mpconSubflows mptcpCon) of 
  [] -> Nothing
  [x] -> Just x
  (_:_) -> error "There can be only one master subflow"



-- |Adds a subflow to the connection
-- Runs some extra checks
-- TODO compose with mptcpConnAddLocalId
mptcpConnAddSubflow :: MptcpConnection -> MptcpSubflow -> MptcpConnection
mptcpConnAddSubflow mptcpConn sf =
    -- TODO check that there are no duplicates / only one master etc
    (mptcpConn { mpconSubflows = Set.insert sf (mpconSubflows mptcpConn) })


-- |Remove subflow from an MPTCP connection
mptcpConnRemoveSubflow :: MptcpConnection -> MptcpSubflow -> MptcpConnection
mptcpConnRemoveSubflow con sf = con {
  mpconSubflows = Set.delete sf (mpconSubflows con)
  -- TODO remove associated local/remote Id ?
}

