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
import Net.Tcp
-- import Net.Tcp.Definitions (TcpConnection(..))
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


-- add a maybe ?
getMasterSubflow :: MptcpConnection -> TcpConnection
getMasterSubflow mptcpCon = head $ filter (\sf -> localId sf == 0) (Set.toList $ subflows mptcpCon)

-- | Remote port
data RemoteId = RemoteId {
    remoteAddress :: IP
  , remotePort  :: Word16
}

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


