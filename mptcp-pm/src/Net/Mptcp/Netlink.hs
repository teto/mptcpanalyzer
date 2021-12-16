module Net.Mptcp.Netlink
where

import System.Linux.Netlink.Constants
import System.Linux.Netlink.GeNetlink

import Data.Word (Word8, Word16, Word32)
import System.Linux.Netlink
-- import System.Linux.Netlink.Constants
import Net.IP
import Net.Mptcp.Types
-- import Net.Mptcp.Constants
import Data.Bits ((.|.))
-- import qualified Data.Map as Map

data MptcpSocket = MptcpSocket NetlinkSocket Word16

-- |Represents every possible setting sent/received on the netlink channel
data MptcpAttribute =
    MptcpAttrToken MptcpToken |
    -- v4 or v6, AddressFamily is a netlink def
    SubflowFamily AddressFamily | -- ^ should be Word16 too
    -- remote/local ?
    RemoteLocatorId Word8 |
    LocalLocatorId Word8 |
    SubflowSourceAddress IP |
    SubflowDestAddress IP |
    SubflowSourcePort Word16 |
    SubflowDestPort Word16 |
    SubflowMaxCwnd Word32 |
    SubflowBackup Word8 |
    SubflowInterface Word32
    deriving (Show, Eq)


-- instance Show MptcpSocket where
--
showMptcpSocket :: MptcpSocket -> String
showMptcpSocket  (MptcpSocket _ fid) = "Mptcp netlink socket: " ++ show fid

type MptcpPacket = GenlPacket NoData


--
-- The message type/ flag / sequence number / pid  (0 => from the kernel)
-- https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/netlink.h#L54
fixHeader :: MptcpSocket -> Bool -> MptcpPacket -> MptcpPacket
fixHeader _ dump pkt = let
    myHeader = Header 0 (flags .|. fNLM_F_ACK) 0 0
    flags = if dump then fNLM_F_REQUEST .|. fNLM_F_MATCH .|. fNLM_F_ROOT else fNLM_F_REQUEST
  in
    pkt { packetHeader = myHeader }
