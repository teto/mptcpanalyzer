{-
Module:   Net.Mptcp.V1.Commands
Description :  Description
Maintainer  : matt
Portability : Linux
-}
{-# LANGUAGE CPP #-}
module Net.Mptcp.V1.Commands (
    attrToPair
  , newSubflowPkt
  , makeAttribute
  , resetConnectionPkt
  , subflowFromAttributes
  ) where

-- mptcp-pm
import Net.Mptcp.V1.Constants
import Net.Mptcp.Netlink
import Net.Mptcp.Types
import Net.Mptcp.Utils
import Net.Tcp.Definitions


import Control.Exception (assert)
import Data.Word (Word16, Word8, Word32)
import Data.Serialize.Get
import Data.Serialize.Put
import Data.ByteString
import qualified Data.Map as Map
import Net.IP
import Net.IPv4
import Net.IPv6
import Net.IPAddress
import System.Linux.Netlink
import System.Linux.Netlink.Constants (fNLM_F_ACK, fNLM_F_REQUEST, fNLM_F_MATCH, fNLM_F_ROOT, eAF_INET)
import Data.Bits ((.|.))
import System.Linux.Netlink.GeNetlink
import Data.Maybe
import Debug.Trace

genV4SubflowAddress :: MptcpAttr -> IPv4 -> (Int, ByteString)
genV4SubflowAddress attr ip = (fromEnum attr, runPut $ putWord32be w32)
  where
    w32 = getIPv4 ip

genV6SubflowAddress :: MptcpAttr -> IPv6 -> (Int, ByteString)
genV6SubflowAddress _addr = undefined

mptcpListToAttributes :: [MptcpAttribute] -> Attributes
mptcpListToAttributes attrs = Map.fromList $ Prelude.map attrToPair attrs


{-|
  Generates an Mptcp netlink request
TODO we could fake the Word16/Flag and
-}
genMptcpRequest :: Word16 -- ^the family id
                -> MptcpGenlEvent -- ^The MPTCP command
                -> Bool           -- ^Dump answer (returns EOPNOTSUPP if not possible)
                -- -> Attributes
                -> [MptcpAttribute]
                -> MptcpPacket
genMptcpRequest fid cmd dump attrs =
  let
    myHeader = Header (fromIntegral fid) (flags .|. fNLM_F_ACK) 0 0
    geheader = GenlHeader word8Cmd mptcpGenlVer
    flags = if dump then fNLM_F_REQUEST .|. fNLM_F_MATCH .|. fNLM_F_ROOT else fNLM_F_REQUEST
    word8Cmd = fromIntegral (fromEnum cmd) :: Word8

    pkt = Packet myHeader (GenlData geheader NoData) (mptcpListToAttributes attrs)
    -- TODO run an assert on the list filter
    -- hasTokenAttr = Prelude.any (isAttribute (MptcpAttrToken 0)) attrs
  in
    -- assert hasTokenAttr 
    pkt

hasFamily :: [MptcpAttribute] -> Bool
hasFamily = Prelude.any (isAttribute (SubflowFamily eAF_INET))

--
-- inspired by netlink cATA :: CtrlAttribute -> (Int, ByteString)
attrToPair :: MptcpAttribute -> (Int, ByteString)
attrToPair (MptcpAttrToken token) = (fromEnum MPTCP_ATTR_TOKEN, runPut $ putWord32host token)
attrToPair (RemoteLocatorId loc) = (fromEnum MPTCP_ATTR_REM_ID, runPut $ putWord8 loc)
attrToPair (LocalLocatorId loc) = (fromEnum MPTCP_ATTR_LOC_ID, runPut $ putWord8 loc)
attrToPair (SubflowFamily fam) = let
        fam8 = (fromIntegral $ fromEnum fam) :: Word16
    in (fromEnum MPTCP_ATTR_FAMILY, runPut $ putWord16host fam8)

attrToPair ( SubflowInterface idx) = (fromEnum MPTCP_ATTR_IF_IDX, runPut $ putWord32host idx)
attrToPair ( SubflowSourcePort port) = (fromEnum MPTCP_ATTR_SPORT, runPut $ putWord16host port)
attrToPair ( SubflowDestPort port) = (fromEnum MPTCP_ATTR_DPORT, runPut $ putWord16host port)
attrToPair ( SubflowMaxCwnd limit) =
#ifdef EXPERIMENTAL_CWND 
  (fromEnum MPTCP_ATTR_CWND, runPut $ putWord32host limit)
#else
  error "not supported"
#endif
attrToPair (SubflowBackup prio) = (fromEnum MPTCP_ATTR_BACKUP, runPut $ putWord8 prio)
-- TODO should depend on the ip putWord32be w32
attrToPair (SubflowSourceAddress addr) =
  case_ (genV4SubflowAddress MPTCP_ATTR_SADDR4) (genV6SubflowAddress MPTCP_ATTR_SADDR6) addr
attrToPair (SubflowDestAddress addr) =
  case_ (genV4SubflowAddress MPTCP_ATTR_DADDR4) (genV6SubflowAddress MPTCP_ATTR_DADDR6) addr

-- TODO prefix with 'e' for enum
-- Map.lookup (fromEnum attr) m
-- getAttribute :: MptcpAttr -> Attributes -> Maybe MptcpAttribute
-- getAttribute attr m
--     | attr == MPTCP_ATTR_TOKEN = Nothing
--     | otherwise = Nothing

-- getAttribute :: (Int, ByteString) -> CtrlAttribute
-- getAttribute (i, x) = fromMaybe (CTRL_ATTR_UNKNOWN i x) $makeAttribute i x

-- getW16 :: ByteString -> Maybe Word16
-- getW16 x = e2M (runGet g16 x)

-- getW32 :: ByteString -> Maybe Word32
-- getW32 x = e2M (runGet g32 x)

-- "either2Maybe"
e2M :: Either a b -> Maybe b
e2M (Right x) = Just x
e2M _         = Nothing

convertAttributesIntoMap :: Attributes -> Map.Map MptcpAttr MptcpAttribute
convertAttributesIntoMap attrs = let
      customFn k val = fromJust (makeAttribute k val)
      newMap = Map.mapWithKey (customFn) attrs
  in
      Map.mapKeys (toEnum) newMap

-- TODO rename fromMap
makeAttributeFromMaybe :: MptcpAttr -> Attributes -> Maybe MptcpAttribute
makeAttributeFromMaybe attrType attrs =
  let res = Map.lookup (fromEnum attrType) attrs in
  case res of
    Nothing         -> error $ "Could not build attr " ++ show attrType
    Just bytestring -> makeAttribute (fromEnum attrType) bytestring


remoteIdFromAttributes :: Attributes -> RemoteId
remoteIdFromAttributes attrs = let
    (SubflowDestPort dport) = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_DPORT attrs
    -- (SubflowFamily _) = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_FAMILY attrs
    SubflowDestAddress destIp = ipFromAttributes False attrs
    -- (SubflowDestPort dport) = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_DPORT attrs
  in
    RemoteId destIp dport


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


dumpAttribute :: Int -> ByteString -> String
dumpAttribute attrId value =
  show $ makeAttribute attrId value

-- https://stackoverflow.com/questions/47861648/a-general-way-of-comparing-constructors-of-two-terms-in-haskell?noredirect=1&lq=1
-- attrToPair ( SubflowSourcePort port) = (fromEnum MPTCP_ATTR_SPORT, runPut $ putWord8 loc)
isAttribute :: MptcpAttribute -- ^ to compare with
               -> MptcpAttribute -- ^to compare to
               -> Bool
isAttribute ref toCompare = fst (attrToPair toCompare) == fst (attrToPair ref)

-- create a fake LocalLocatorId
hasLocAddr :: [MptcpAttribute] -> Bool
hasLocAddr attrs = Prelude.any (isAttribute (LocalLocatorId 0)) attrs

-- need to prepare a request
-- type GenlPacket a = Packet (GenlData a)
-- REQUIRES: LOC_ID / TOKEN
-- TODO pass TcpConnection
resetConnectionPkt :: MptcpSocket -> [MptcpAttribute] -> MptcpPacket
resetConnectionPkt (MptcpSocket _sock fid) attrs =
    error "reset not implemented yet"
    -- let
    -- _cmd = MPTCP_CMD_REMOVE
  -- in
    -- assert (hasLocAddr attrs) $ genMptcpRequest fid MPTCP_CMD_REMOVE False attrs

connectionAttrs :: MptcpConnection -> [MptcpAttribute]
connectionAttrs con = [ MptcpAttrToken $ connectionToken con ]

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

-- sport/backup/intf are optional
newSubflowPkt :: MptcpSocket -> MptcpConnection -> TcpConnection -> MptcpPacket
newSubflowPkt (MptcpSocket _ fid) mptcpCon sf = 
    error "undefined"
    -- assert (hasFamily attrs) pkt
    -- where 
    --   _cmd = MPTCP_CMD_SUB_CREATE
    --   attrs = connectionAttrs mptcpCon ++ subflowAttrs sf
    --   pkt = genMptcpRequest fid MPTCP_CMD_SUB_CREATE False attrs

-- | Builds an MptcpAttribute from
makeAttribute :: Int -- ^ MPTCP_ATTR_TOKEN value
                  -> ByteString
                  -> Maybe MptcpAttribute
makeAttribute i val =
  case toEnum i of
    MPTCP_ATTR_TOKEN ->
      case readToken val of
        Left err         -> error "could not decode"
        Right mptcpToken -> Just $ MptcpAttrToken mptcpToken

    -- TODO fix
    MPTCP_ATTR_FAMILY ->
        case runGet getWord16host val of
          -- assert it's eAF_INET or eAF_INET6
          Right x -> Just $ SubflowFamily (toEnum ( fromIntegral x :: Int))
          _       -> Nothing
    MPTCP_ATTR_SADDR4 -> SubflowSourceAddress <$> fromIPv4 <$> e2M ( getIPv4FromByteString val)
    MPTCP_ATTR_DADDR4 -> SubflowDestAddress <$> fromIPv4 <$> e2M (getIPv4FromByteString val)
    MPTCP_ATTR_SADDR6 -> SubflowSourceAddress <$> fromIPv6 <$> e2M (getIPv6FromByteString val)
    MPTCP_ATTR_DADDR6 -> SubflowDestAddress <$> fromIPv6 <$> e2M (getIPv6FromByteString val)
    MPTCP_ATTR_SPORT -> SubflowSourcePort <$> port where port = e2M $ runGet getWord16host val
    MPTCP_ATTR_DPORT -> SubflowDestPort <$> port where port = e2M $ runGet getWord16host val
    MPTCP_ATTR_LOC_ID -> Just (LocalLocatorId $ readLocId $ Just val )
    MPTCP_ATTR_REM_ID -> Just (RemoteLocatorId $ readLocId $ Just val )
    MPTCP_ATTR_IF_IDX -> trace ("if_idx: " ++ show val) (
             case runGet getWord32be val of
                Right x -> Just $ SubflowInterface x
                _       -> Nothing)
    -- backup is u8
    MPTCP_ATTR_BACKUP -> Just (SubflowBackup $ readLocId $ Just val )
    MPTCP_ATTR_ERROR -> trace "makeAttribute ERROR" Nothing
    MPTCP_ATTR_TIMEOUT -> undefined
#ifdef EXPERIMENTAL_CWND
    MPTCP_ATTR_CWND -> undefined
#endif
    MPTCP_ATTR_FLAGS -> trace "makeAttribute ATTR_FLAGS" Nothing
    MPTCP_ATTR_UNSPEC -> undefined
    MPTCP_ATTR_RESET_REASON -> undefined
    MPTCP_ATTR_RESET_FLAGS -> undefined

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
    SubflowSourceAddress srcIp' = fromJust $ makeAttributeFromMaybe srcAttr attrs
        -- eAF_INET6 -> fromJust $ makeAttributeFromMaybe MPTCP_ATTR_SADDR6 attrs
        -- ipFromAttributes True attrs
    srcAttr = case family of
        2 -> MPTCP_ATTR_SADDR4
        10 -> MPTCP_ATTR_SADDR6
        _ -> error "Unsupported address family"
    SubflowDestAddress dstIp' = fromJust $ makeAttributeFromMaybe dstAttr attrs
    dstAttr = case family of
        2 -> MPTCP_ATTR_DADDR4
        10 -> MPTCP_ATTR_DADDR6
        _ -> error "Unsupported address family"
    LocalLocatorId lid = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_LOC_ID attrs
    RemoteLocatorId rid = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_REM_ID attrs
    SubflowInterface intfId = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_IF_IDX attrs
    SubflowFamily family = fromJust $ makeAttributeFromMaybe MPTCP_ATTR_FAMILY attrs

    -- sfFamily = getPort $ fromJust (Map.lookup (fromEnum MPTCP_ATTR_FAMILY) attrs)
    prio = Nothing   -- (SubflowPriority N)
  in
    -- TODO fix sfFamily
    TcpConnection srcIp' dstIp' sport dport prio lid rid (Just intfId)

