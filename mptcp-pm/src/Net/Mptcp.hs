{-|
Module      : Net.Mptcp
Description : Implementation of mptcp netlink path manager
Maintainer  : matt
Stability   : testing
Portability : Linux

OverloadedStrings allows Aeson to convert
-}
{-# LANGUAGE DeriveGeneric, CPP #-}
{-# LANGUAGE OverloadedStrings #-}
module Net.Mptcp (
  -- * Types
  MptcpConnection (..)
  , MptcpPacket
  , MptcpSocket (..)
  , MptcpToken
  , dumpAttribute
  , mptcpConnAddSubflow
  , mptcpConnRemoveSubflow
  , capCwndPkt
  , subflowFromAttributes
  , showMptcpSocket
  , readToken
  , remoteIdFromAttributes
)
where

-- mptcp-pm
import Net.Mptcp.Netlink
import Net.Mptcp.Types
import Net.Mptcp.Constants
import Net.Mptcp.V0.Commands
import Net.Tcp
import Net.SockDiag ()
import Net.IPAddress

-- hackage
-- import Control.Exception (assert)

import qualified Data.Map as Map
import Data.Word (Word16, Word32, Word8)
import System.Linux.Netlink hiding (makeSocket)
-- import System.Linux.Netlink (query, Packet(..))
-- import System.Linux.Netlink.GeNetlink.Control
import Data.ByteString (ByteString)
import Data.Maybe (fromJust)

import Data.Serialize.Get
-- import 

import Control.Concurrent ()
import Control.Monad.Trans.State ()
import Data.List ()
import qualified Data.Set as Set
-- import Debug.Trace
-- import System.Linux.Netlink.Constants




remoteIdFromAttributes :: Attributes -> RemoteId
remoteIdFromAttributes attrs = let
    (SubflowDestPort dport) = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_DPORT attrs
    -- (SubflowFamily _) = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_FAMILY attrs
    SubflowDestAddress destIp = ipFromAttributes False attrs
    -- (SubflowDestPort dport) = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_DPORT attrs
  in
    RemoteId destIp dport



-- |Adds a subflow to the connection
-- TODO compose with mptcpConnAddLocalId
mptcpConnAddSubflow :: MptcpConnection -> TcpConnection -> MptcpConnection
mptcpConnAddSubflow mptcpConn sf =
  -- trace ("Adding subflow" ++ show sf)
    mptcpConnAddLocalId
        (mptcpConnAddRemoteId
            (mptcpConn { subflows = Set.insert sf (subflows mptcpConn) })
            (remoteId sf)
        )
        (localId sf)

    -- , localIds = Set.insert (localId sf) (localIds mptcpConn)
    -- , remoteIds = Set.insert (remoteId sf) (remoteIds mptcpConn)
  -- }


-- |Add local id
mptcpConnAddLocalId :: MptcpConnection
                       -> Word8 -- ^Local id to add
                       -> MptcpConnection
mptcpConnAddLocalId con locId = con { localIds = Set.insert (locId) (localIds con) }


-- |Add remote id
mptcpConnAddRemoteId :: MptcpConnection
                       -> Word8 -- ^Remote id to add
                       -> MptcpConnection
mptcpConnAddRemoteId con remId = con { localIds = Set.insert (remId) (remoteIds con) }

-- |Remove subflow from an MPTCP connection
mptcpConnRemoveSubflow :: MptcpConnection -> TcpConnection -> MptcpConnection
mptcpConnRemoveSubflow con sf = con {
  subflows = Set.delete sf (subflows con)
  -- TODO remove associated local/remote Id ?
}


getPort :: ByteString -> Word16
getPort val =
  case (runGet getWord16host val) of
    Left _     -> 0
    Right port -> port






-- LocId => Word8
readLocId :: Maybe ByteString -> LocId
readLocId maybeVal = case maybeVal of
  Nothing -> error "Missing locator id"
  Just val -> case runGet getWord8 val of
    -- TODO generate an error here !
    Left _      -> error "Could not get locId !!"
    Right locId -> locId
  -- runGet getWord8 val

-- doDumpLoop :: MyState -> IO MyState
-- doDumpLoop myState = do
--     let (MptcpSocket simpleSock fid) = socket myState
--     results <- recvOne' simpleSock ::  IO [Either String MptcpPacket]
--     -- TODO retrieve packets
--     mapM_ (inspectResult myState) results
--     newState <- doDumpLoop myState
--     return newState


-- data MptcpAttributes = MptcpAttributes {
--     connToken :: Word32
--     , localLocatorID :: Maybe Word8
--     , remoteLocatorID :: Maybe Word8
--     , family :: Word16 -- Remove ?
--     -- |Pointer to the Attributes map used to build this struct. This is purely
--     -- |for forward compat, please file a feature report if you have to use this.
--     , staSelf       :: Attributes
-- } deriving (Show, Eq, Read)

-- Wouldn't it be easier to work with ?
-- data MptcpEvent = NewConnection {
-- }



-- |Retreive IP
-- TODO could check/use addressfamily as well
ipFromAttributes :: Bool  -- ^True if source
                    -> Attributes -> MptcpAttribute
ipFromAttributes True attrs =
    case makeAttributeFromMaybe MPTCP_ATTR_SADDR4 attrs of
      Just ip -> ip
      Nothing -> case makeAttributeFromMaybe MPTCP_ATTR_SADDR6 attrs of
        Just ip -> ip
        Nothing -> error "could not get the src IP"

ipFromAttributes False attrs =
    case makeAttributeFromMaybe MPTCP_ATTR_DADDR4 attrs of
      Just ip -> ip
      Nothing -> case makeAttributeFromMaybe MPTCP_ATTR_DADDR6 attrs of
        Just ip -> ip
        Nothing -> error "could not get dest IP"

-- mptcpAttributesToMap :: [MptcpAttribute] -> Attributes
-- mptcpAttributesToMap attrs =
--   Map.fromList $map mptcpAttributeToTuple attrs

-- |Converts / should be a maybe ?
-- TODO simplify
subflowFromAttributes :: Attributes -> TcpConnection
subflowFromAttributes attrs =
  let
    -- expects a ByteString
    SubflowSourcePort sport = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_SPORT attrs
    SubflowDestPort dport = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_DPORT attrs
    SubflowSourceAddress _srcIp =  ipFromAttributes True attrs
    SubflowDestAddress _dstIp = ipFromAttributes False attrs
    LocalLocatorId lid = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_LOC_ID attrs
    RemoteLocatorId rid = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_REM_ID attrs
    SubflowInterface intfId = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_IF_IDX attrs
    -- sfFamily = getPort $ fromJust (Map.lookup (fromEnum MPTCP_ATTR_FAMILY) attrs)
    prio = Nothing   -- (SubflowPriority N)
  in
    -- TODO fix sfFamily
    TcpConnection _srcIp _dstIp sport dport prio lid rid (Just intfId)





-- pass token ?
subflowAttrs :: TcpConnection -> [MptcpAttribute]
subflowAttrs con = [
    LocalLocatorId $ localId con
    , RemoteLocatorId $ remoteId con
    , SubflowFamily $ getAddressFamily (dstIp con)
    , SubflowDestAddress $ dstIp con
    , SubflowDestPort $ dstPort con
    -- should fail if doesn't exist
    , SubflowInterface $ fromJust $ subflowInterface con
    -- https://github.com/multipath-tcp/mptcp/issues/338
    , SubflowSourceAddress $ srcIp con
    , SubflowSourcePort $ srcPort con
  ]

-- |Generate a request to create a new subflow
capCwndPkt :: MptcpSocket -> MptcpConnection
              -> Word32  -- ^Limit to apply to congestion window
              -> TcpConnection -> Either String MptcpPacket
capCwndPkt (MptcpSocket _ fid) mptcpCon limit sf =
#ifdef EXPERIMENTAL_CWND
    assert (hasFamily attrs) (Right pkt)
    where
        oldPkt = genMptcpRequest fid MPTCP_CMD_SND_CLAMP_WINDOW False attrs
        pkt = oldPkt { packetHeader = (packetHeader oldPkt) { messagePID = 42 } }
        attrs = connectionAttrs mptcpCon
              ++ [ SubflowMaxCwnd limit ]
              ++ subflowAttrs sf
#else
    error "support for capping Cwnds not compiled"
#endif

connectionAttrs :: MptcpConnection -> [MptcpAttribute]
connectionAttrs con = [ MptcpAttrToken $ connectionToken con ]

