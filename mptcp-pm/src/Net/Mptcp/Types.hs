{-# LANGUAGE DeriveGeneric, CPP #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE OverloadedStrings #-}
module Net.Mptcp.Types
where

import GHC.Generics
import Data.Word
import Data.Aeson
import qualified Data.Set as Set
import Net.IP
import Net.Tcp.Definitions (TcpConnection)
-- import Data.ByteString

type MptcpToken = Word32
type LocId    = Word8

--
-- |Same as SockDiagMetrics
-- data SubflowWithMetrics = SubflowWithMetrics {
--   subflowSubflow :: TcpConnection
--     -- for now let's retain DiagTcpInfo  only
--   , metrics :: [SockDiagExtension]
-- }

-- |Holds MPTCP level information
data MptcpConnection = MptcpConnection {
    connectionToken :: MptcpToken
  -- use SubflowWithMetrics instead ?!
  -- , subflows :: Set.Set [TcpConnection]
  , subflows      :: Set.Set TcpConnection
  , localIds      :: Set.Set Word8  -- ^ Announced addresses
  , remoteIds     :: Set.Set Word8   -- ^ Announced addresses

  -- Might be reworked/moved in an Enriched/Tracker structure afterwards
  , get_caps_prog :: Maybe FilePath
} deriving (Show, Generic, FromJSON)


-- | Remote port
data RemoteId = RemoteId {
    remoteAddress :: IP
  , remotePort  :: Word16
}

-- TODO revisit where to put it ?
-- data PMCommand = Unspec | AddAddr | DelAddr | GetAddr | FlushAddrs | SetLimits | GetLimits | SetFlags
--  | MPTCP_PM_CMD_ADD_ADDR
--  | MPTCP_PM_CMD_DEL_ADDR
--  | MPTCP_PM_CMD_GET_ADDR
--  | MPTCP_PM_CMD_FLUSH_ADDRS
--  | MPTCP_PM_CMD_SET_LIMITS
--  | MPTCP_PM_CMD_GET_LIMITS
--  | MPTCP_PM_CMD_SET_FLAGS

--  export to the format expected by mptcpnumerics
-- could be automatically generated ?
-- toJSON :: MptcpConnection -> Value
instance ToJSON MptcpConnection where
  toJSON mptcpConn = object
    [ "name" .= toJSON (show $ connectionToken mptcpConn)
    , "sender" .= object [
          -- TODO here we could read from sysctl ? or use another SockDiagExtension
          "snd_buffer" .= toJSON (40 :: Int)
          , "capabilities" .= object []
        ]
    , "capabilities" .= object ([])
    -- TODO generated somewhere else
    -- , "subflows" .= object ([])
    ]


