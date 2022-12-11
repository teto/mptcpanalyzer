{-|
Module      : Net.Mptcp.Connection
Description : Basic MPTCP connection description
Maintainer  : matt
License     : GPL-3
-}
{-# LANGUAGE TemplateHaskell, DerivingStrategies, DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}
module Net.Mptcp.Connection (
  -- * Types
    MptcpConnection(..)
  , MptcpSubflow(..)
  , MptcpEndpointConfiguration(..)
  , showMptcpConnectionText

  , mptcpConnAddSubflow
  , mptcpConnRemoveSubflow
  , getMasterSubflow
  , getSubflowFromStreamId

  , tokenBelongToConnection
)
where

import Net.IP
import Net.Tcp
import Net.Stream

-- import MptcpAnalyzer.Arti
import qualified Data.Set as Set
import Data.Text as TS
import Data.Word (Word16, Word32, Word64, Word8)
-- import MptcpAnalyzer.ArtificialFields

data MptcpEndpointConfiguration = MptcpEndpointConfiguration {
  -- |key exchanged during the handshake
    key :: Word64
  , token :: Word32
  -- ^Hash of the server key
  , version :: Int -- ^ 0 or 1 at least for now
  -- , mecIdsn :: Word64
  -- ^ Initial data sequence number
  } deriving (Show, Eq)


-- | Holds all necessary information about a multipath TCP connection
-- TODO add an imcomplete constructor ?
data MptcpConnection = MptcpConnection {
  -- todo prefix as mpcon
  -- |The wireshark mptcp.stream identifier (a number)
    mpconStreamId :: StreamIdMptcp
  -- |Server key exchanged during the handshake
  , serverConfig :: MptcpEndpointConfiguration
  , clientConfig :: MptcpEndpointConfiguration
  -- | Mptcp version negotiated during the handshake Not implemented yet ?
  -- , mptcpNegotiatedVersion :: Word8  -- ^ 0 or 1 at least for now
  -- ^ List of past/present/future subflows seen during communication
  , subflows :: Set.Set MptcpSubflow

-- Ord to be able to use fromList
} deriving (Show, Eq)


-- | Extension of @TcpConnection@
-- master subflow has implicit addrid 0
-- TODO add start/end dates ?
data MptcpSubflow = MptcpSubflow {
        connection :: TcpConnection
      -- shall keep token instead ? or as a boolean ?
      -- Todo token
      -- , sfMptcpDest :: ConnectionRole -- ^ Destination
      , joinToken :: Maybe Word32 -- ^ token of sendkey to authentify itself, Nothing -> Master subflow
      , priority :: Maybe Word8 -- ^subflow priority
      , localId :: Word8  -- ^ Convert to AddressFamily
      , remoteId :: Word8
      --conTcp TODO remove could be deduced from srcIp / dstIp ?
      -- allow
      , interface :: Maybe Word32 -- ^Interface of Maybe ? why a maybe ?
      -- Maybe Word32 -- ^Interface of Maybe ? why a maybe ?
    } deriving (Show, Eq)
    -- deriving Ord via TcpConnection

instance Ord MptcpSubflow where
  con1 `compare` con2 = con1.connection `compare` con2.connection 


tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show

-- |Pretty print an MPTCP connection
showMptcpConnectionText :: MptcpConnection -> Text
showMptcpConnectionText con =
  -- showIp (srcIp con) <> ":" <> tshow (srcPort con) <> " -> " <> showIp (dstIp con) <> ":" <> tshow (dstPort con)
  tpl <> "\nSubflows:\n" <> TS.unlines (Prelude.map (showTcpConnectionText . (.connection)) (Set.toList $  con.subflows))
  where
    -- todo show version
    tpl :: Text
    tpl = TS.unlines [
        "Server key/token: " <> tshow (con.serverConfig.key) <> "/" <> tshow (con.serverConfig.token)
      , "Client key/token: " <> tshow (con.clientConfig.key) <> "/" <> tshow (con.clientConfig.token)
      ]

---- add a maybe ?
getMasterSubflow :: MptcpConnection -> Maybe MptcpSubflow
getMasterSubflow mptcpCon = case Prelude.filter (\sf ->  sf.localId == 0) (Set.toList mptcpCon.subflows) of
  [] -> Nothing
  [x] -> Just x
  (_:_) -> error "There can be only one master subflow"


getSubflowFromStreamId :: MptcpConnection -> StreamIdTcp -> Maybe MptcpSubflow
getSubflowFromStreamId con streamId = 
  case Prelude.filter (\sf -> sf.connection.streamId == streamId) (Set.toList con.subflows) of 
    [] -> Nothing
    (x:_) -> Just x

-- TODO test
tokenBelongToConnection :: Word32 -> MptcpConnection -> Bool
tokenBelongToConnection rcvToken con =
  if rcvToken == con.clientConfig.token then
    True
  else if rcvToken == con.serverConfig.token then
    True
  else
    False

-- |Adds a subflow to the connection
-- Runs some extra checks
-- TODO compose with mptcpConnAddLocalId
mptcpConnAddSubflow :: MptcpConnection -> MptcpSubflow -> MptcpConnection
mptcpConnAddSubflow mptcpConn sf =
  -- TODO check that there are no duplicates / only one master etc
  (mptcpConn { subflows = Set.insert sf mptcpConn.subflows })


-- |Remove subflow from an MPTCP connection
mptcpConnRemoveSubflow :: MptcpConnection -> MptcpSubflow -> MptcpConnection
mptcpConnRemoveSubflow con sf = con {
  subflows = Set.delete sf con.subflows
  -- TODO remove associated local/remote Id ?
}

