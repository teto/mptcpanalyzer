{-|
Description : Implementation of mptcp netlink path manager
module: Net.Mptcp.PathManager.V1.NdiffPorts
Maintainer  : matt
Portability : Linux
-}
module Net.Mptcp.PathManager.V1.NdiffPorts (
  -- TODO don't export / move to its own file
    ndiffports
  , meshPathManager
  , nportsOnMasterEstablishement
) where

import Data.Maybe (fromJust)
import qualified Data.Set as Set
import Debug.Trace
import Net.Mptcp
import Net.Stream
import Net.Mptcp.PathManager
-- import Net.Mptcp.Types
import Net.Tcp.Connection
import Net.Mptcp.V1.Commands
import Net.Mptcp.Netlink


-- These should be plugins

ndiffports :: PathManager
ndiffports = PathManager {
    name = "ndiffports"
  , onMasterEstablishement = nportsOnMasterEstablishement
}

{-
  Generate requests
TODO it iterates over local interfaces but not
-}
nportsOnMasterEstablishement :: MptcpSocket -> MptcpConnection -> ExistingInterfaces -> [MptcpPacket]
nportsOnMasterEstablishement mptcpSock mptcpCon paths = do
  map (newSublowPacketFromPort ) [3456]
  where
    generatedCon port = let
        master = fromJust (getMasterSubflow mptcpCon)
      in
        master { sfConn = (sfConn master) { conTcpClientPort = port } }
    newSublowPacketFromPort port = newSubflowPkt mptcpSock mptcpCon (generatedCon port)

  -- TODO create #X subflows
  -- iterate

-- | Creates a subflow between each pair of (client, server) interfaces
meshPathManager :: PathManager
meshPathManager = PathManager {
  name = "mesh"
  , onMasterEstablishement = meshOnMasterEstablishement
}



-- per interface
--  TODO check if there is already an interface with this connection
meshGenPkt :: MptcpSocket -> MptcpConnection -> NetworkInterface -> [MptcpPacket] -> [MptcpPacket]
meshGenPkt mptcpSock mptcpCon intf pkts =

    if traceShow (intf) (interfaceId intf == (fromJust $ sfInterface masterSf)) then
        pkts
    else
        pkts ++ [newSubflowPkt mptcpSock mptcpCon generatedSf]
    where
        generatedSf = MptcpSubflow {
            sfConn = generatedCon
          , sfJoinToken = Nothing
          , sfPriority = Nothing
          -- TODO fix this
          , sfLocalId = fromIntegral $ interfaceId intf    -- how to get it ? or do I generate it ?
          , sfRemoteId = sfRemoteId masterSf
          , sfInterface = Just $ interfaceId intf
        }
        generatedCon = (sfConn masterSf) {
            conTcpClientPort = 0  -- let the kernel handle it
          -- , conTcpServerPort = (conTcpServerPort . sfConn) masterSf
          , conTcpClientIp = ipAddress intf
          -- , conTcpServerIp =  (conTcpServerIp . sfConn) masterSf  -- same as master
          , conTcpStreamId = StreamId 0
          }

        masterSf = (fromJust . getMasterSubflow) mptcpCon


{-
  Generate requests
it iterates over local interfaces and try to connect
-}
meshOnMasterEstablishement :: MptcpSocket -> MptcpConnection -> ExistingInterfaces -> [MptcpPacket]
meshOnMasterEstablishement mptcpSock con paths = do
  foldr (meshGenPkt mptcpSock con) [] paths



