{-# OPTIONS_GHC -Wno-orphans #-}
{-# LANGUAGE DeriveGeneric, CPP #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE OverloadedStrings #-}
module Net.Mptcp.Types
where

import Data.Word
import Data.Aeson
import Net.IP
import Net.Mptcp.Connection

--type MptcpToken = Word32
--type LocId    = Word8
----
---- |Same as SockDiagMetrics
---- data SubflowWithMetrics = SubflowWithMetrics {
----   subflowSubflow :: TcpConnection
----     -- for now let's retain DiagTcpInfo  only
----   , metrics :: [SockDiagExtension]
---- }

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
    [ "name" .= toJSON (show $ mptcpConn.clientConfig.token)
    , "sender" .= object [
          -- TODO here we could read from sysctl ? or use another SockDiagExtension
          "snd_buffer" .= toJSON (40 :: Int)
          , "capabilities" .= object []
        ]
    , "capabilities" .= object ([])
    -- TODO generated somewhere else
    -- , "subflows" .= object ([])
    ]


