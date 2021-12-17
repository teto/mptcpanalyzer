{-
Module:  Net.Mptcp.PathManager
Description :
Maintainer  : matt
Portability : Linux

Trying to come up with a userspace abstraction for MPTCP path management

-}


module Net.Mptcp.PathManager (
    PathManager (..)
    , NetworkInterface(..)
    , AvailablePaths
    , PathManagerConfig
    , loadConnectionsFromFile
    , mapIPtoInterfaceIdx
    , defaultPathManagerConfig
    -- TODO don't export / move to its own file
    , handleAddr
    , globalInterfaces
) where

import Prelude hiding (concat, init)

import Control.Concurrent
import Data.Aeson
import qualified Data.Map as Map
import Data.Word (Word32)
import Debug.Trace
import Net.IP
import Net.Mptcp
import Net.Tcp
import System.Linux.Netlink as NL
import qualified System.Linux.Netlink.Route as NLR
-- import System.Linux.Netlink.Constants (eRTM_NEWADDR)
import System.Linux.Netlink.Constants as NLC
-- import qualified System.Linux.Netlink.Simple as NLS
import Data.ByteString (ByteString, empty)
import Data.ByteString.Char8 (init, unpack)
import qualified Data.ByteString.Lazy as BL
import Data.Maybe (fromMaybe)
import Net.IPAddress
import System.IO.Unsafe

{-# NOINLINE globalInterfaces #-}
globalInterfaces :: MVar AvailablePaths
globalInterfaces = unsafePerformIO newEmptyMVar


data PathManagerConfig = PathManagerConfig {
  pmcIgnoreInterfaces :: [String]
}

defaultPathManagerConfig :: PathManagerConfig
defaultPathManagerConfig = PathManagerConfig {
  pmcIgnoreInterfaces = interfacesToIgnore
}

interfacesToIgnore :: [String]
interfacesToIgnore = [
    "virbr0"
  , "virbr1"
  , "nlmon0"
  , "ppp0"
  , "lo"
  ]

-- basically a retranscription of NLR.NAddrMsg
data NetworkInterface = NetworkInterface {
  ipAddress     :: IP,   -- ^ Should be a list or a set
  interfaceName :: String,  -- ^ eth0 / ppp0
  interfaceId   :: Word32  -- ^ refers to addrInterfaceIndex
} deriving Show


-- [NetworkInterface]
type AvailablePaths = Map.Map IP NetworkInterface



-- |
mapIPtoInterfaceIdx :: AvailablePaths -> IP -> Maybe Word32
mapIPtoInterfaceIdx paths ip =
    interfaceId <$> Map.lookup ip paths

-- class AvailableIPsContainer a where

-- | Load a list of connections from a json file
loadConnectionsFromFile :: FilePath -> IO [TcpConnection]
loadConnectionsFromFile filename = do
  -- Log.info ("Loading connections whitelist from " <> tshow filename <> "...")
  filteredConnectionsStr <- BL.readFile filename
  case Data.Aeson.eitherDecode filteredConnectionsStr of
    Left errMsg -> error ("Failed loading " ++ filename ++ ":\n" ++ errMsg)
    Right list  -> return list


-- |Reimplements
-- TODO we should not need the socket
-- onMasterEstablishement
data PathManager = PathManager {
  name                     :: String
    -- interfacesToIgnore :: [String]
  , onMasterEstablishement :: MptcpSocket -> MptcpConnection -> AvailablePaths -> [MptcpPacket]
}

-- } deriving PathManager


handleInterfaceNotification
  :: AddressFamily -> Attributes -> Word32 -> Maybe NetworkInterface
handleInterfaceNotification addrFamily attrs addrIntf =

  -- filter on flags too (UP), should be != LOOPBACK
  -- lo: <LOOPBACK,UP,LOWER_UP> and
  -- eno1: <BROADCAST,MULTICAST,UP,LOWER_UP
  case ifNameM of
    Nothing -> Nothing
    Just ifName -> case (elem ifName interfacesToIgnore ) of
        True  -> Nothing
        False -> Just $ NetworkInterface ip ifName addrIntf
  where
    -- gets the bytestring / assume it always work
  ipBstr = fromMaybe empty (NLR.getIFAddr attrs)
  ifNameBstr = (Map.lookup NLC.eIFLA_IFNAME attrs)
  ifNameM = getString <$> ifNameBstr
  -- ip = getIPFromByteString addrFamily ipBstr
  ip = case (getIPFromByteString addrFamily ipBstr) of
    Right val -> val
    Left err  -> undefined

-- taken from netlink
getString :: ByteString -> String
getString b = unpack (init b)


-- TODO handle remove/new event move to PathManager
-- todo should be pure and let daemon
handleAddr :: PathManagerConfig -> Either String NLR.RoutePacket -> IO ()
handleAddr _ (Left errStr) = putStrLn $ "Error decoding packet: " ++ errStr
handleAddr _ (Right (DoneMsg hdr)) = putStrLn $ "Error decoding packet: " ++ show hdr
handleAddr _ (Right (ErrorMsg hdr errorInt errorBstr)) = putStrLn $ "Error decoding packet: " ++ show hdr
-- TODO need handleMessage pkt
-- family maskLen flags scope addrIntf
handleAddr cfg (Right (Packet hdr pkt attrs)) = do
  (putStrLn $ "received packet" ++ show pkt)
  oldIntfs <- trace "taking MVAR" (takeMVar globalInterfaces)

  let toto = (case pkt of
        arg@NLR.NAddrMsg{} ->
          let resIntf = handleInterfaceNotification (NLR.addrFamily arg) attrs (NLR.addrInterfaceIndex arg)
          in case resIntf of
                Nothing -> oldIntfs
                Just newIntf -> let
                  ip = ipAddress newIntf
                  in if msgType == eRTM_NEWADDR
                        then trace "adding ip" (Map.insert ip newIntf oldIntfs)
                        -- >> putStrLn "Added interface"
                        else if msgType == eRTM_GETADDR
                        then trace "GET_ADDR" oldIntfs

                        else if msgType == eRTM_DELADDR
                        then
                        trace "deleting ip" (Map.delete ip oldIntfs)
                        -- >> putStrLn "Removed interface"
                        else trace "other type" oldIntfs

        -- _ -> error "can't be anything else"
        arg@NLR.NNeighMsg{} -> trace "neighbor msg" oldIntfs
        arg@NLR.NLinkMsg{} -> trace "link msg" oldIntfs
        )

  trace ("putting mvar") (putMVar globalInterfaces $! (toto))

 where
    -- gets the bytestring
    msgType = messageType hdr

-- (arg@DiagTcpInfo{})


---- Updates the list of interfaces
---- should run in background
----
--trackSystemInterfaces :: IO()
--trackSystemInterfaces = do
--  -- check routing information
--  routingSock <- NLS.makeNLHandle (const $ pure ()) =<< NL.makeSocket
--  let cb = NLS.NLCallback (pure ()) (handleAddr . runGet getGenPacket)
--  NLS.nlPostMessage routingSock queryAddrs cb
--  NLS.nlWaitCurrent routingSock
--  dumpSystemInterfaces



-- fullmesh / ndiffports
    -- []

  -- where
  --   -- genPkt NetworkInterface
  --   -- let newSfPkt = newSubflowPkt mptcpSock newSubflowAttrs
  --   newSubflowAttrs = [
  --         MptcpAttrToken $ connectionToken con
  --       ]
  -- ++ (subflowAttrs $ masterSf { srcPort = 0 })
