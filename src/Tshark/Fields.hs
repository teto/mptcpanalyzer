{-
Module      : Tshark.Fields
Description : Interface between wireshark output format and haskell
Maintainer  : matt

This module is in charge of loading TCP packets in a haskell format.
This is done by converting between wireshark formats (.pcapng -> .csv) and
using "Frames" to load the resulting data into a frame.

-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE PackageImports         #-}
module Tshark.Fields
where
import MptcpAnalyzer.Stream

import "mptcp-pm" Net.Tcp (TcpFlag(..))
import Net.IP
import Net.IPv6 (IPv6(..))
import GHC.TypeLits (KnownSymbol)
import Language.Haskell.TH (Name, Q)
import Data.Text (Text)
import Data.Word (Word8, Word16, Word32, Word64)
import Frames.ShowCSV

import Data.Map (Map, fromList, mapKeys)
-- Phantom types
-- data Mptcp
-- data Tcp
-- -- data Protocol = Tcp | Mptcp

-- -- TODO use Word instead
-- newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord )

-- type StreamIdTcp = StreamId
-- type StreamIdMptcp = StreamId

type TcpFlagList = [TcpFlag]
type MbPacketIdList = Maybe [Word64]


type MbMptcpStream = Maybe StreamIdMptcp
type MbMptcpSendKey = Maybe Word64
type MbMptcpVersion = Maybe Int
type MbMptcpExpectedToken = Maybe Word32

type MbMptcpDsn = Maybe Word64
type MbMptcpDack = Maybe Word64
type MbWord64 = Maybe Word64


data TsharkFieldDesc = TsharkFieldDesc {
        tfieldFullname :: Text
        -- ^Full wireshark name of the field
        , tfieldColType :: Name
        -- ^Haskell type so that we can generate the proper raw type via templateHaskell
        , tfieldLabel :: Maybe String
        -- ^Pretty field name used as label in plots
        , tfieldHashable :: Bool
        -- ^Wether to take into account this field when creating the hash of a packet
        -- see hash
    }


type FieldDescriptions = Map Text TsharkFieldDesc

type MbWord32 = Maybe Word32


-- TODO add this ?
-- data Field = FieldPacketId | FieldInterfaceName

-- MUST BE KEPT IN SYNC WITH  Pcap.hs HostCols ORDER INCLUDED !
baseFields :: FieldDescriptions
baseFields = fromList [
    ("packetId", TsharkFieldDesc "frame.number" ''Word64 Nothing False)
    , ("interfaceName", TsharkFieldDesc "frame.interface_name" ''Text Nothing False)
    , ("absTime", TsharkFieldDesc "frame.time_epoch" ''Double Nothing False)
    , ("relTime", TsharkFieldDesc "frame.time_relative" ''Double Nothing False)
    , ("ipSource", TsharkFieldDesc "_ws.col.ipsrc" ''IP (Just "source ip") True)
    , ("ipDest", TsharkFieldDesc "_ws.col.ipdst" ''IP (Just "destination ip") True)
    , ("ipSrcHost", TsharkFieldDesc "ip.src_host" ''Text (Just "source ip hostname") False)
    , ("ipDstHost", TsharkFieldDesc "ip.dst_host" ''Text (Just "destination ip hostname") False)
    , ("tcpStream", TsharkFieldDesc "tcp.stream" ''StreamIdTcp Nothing False)
    , ("tcpSrcPort", TsharkFieldDesc "tcp.srcport" ''Word16 Nothing True)
    , ("tcpDestPort", TsharkFieldDesc "tcp.dstport" ''Word16 Nothing True)
    , ("rwnd", TsharkFieldDesc "tcp.window_size" ''Word32 Nothing True)
    , ("tcpFlags", TsharkFieldDesc "tcp.flags" ''TcpFlagList Nothing True)
    , ("tcpOptionKinds", TsharkFieldDesc "tcp.option_kind" ''Text Nothing True)
    , ("tcpSeq", TsharkFieldDesc "tcp.seq" ''Word32 (Just "Sequence number") True)
    , ("tcpLen", TsharkFieldDesc "tcp.len" ''Word16 (Just "Tcp Len") True)
    , ("tcpAck", TsharkFieldDesc "tcp.ack" ''Word32 (Just "Tcp ACK") True)

    , ("tsval", TsharkFieldDesc "tcp.options.timestamp.tsval" ''MbWord32 (Just "Timestamp val") True)
    , ("tsecr", TsharkFieldDesc "tcp.options.timestamp.tsecr" ''MbWord32 (Just "Timestamp echo-reply") True)

    -- could be computed from the sendKey
    , ("mptcpExpectedToken", TsharkFieldDesc "mptcp.expected_token" ''MbMptcpExpectedToken (Just "Expected token") True)

    , ("mptcpStream", TsharkFieldDesc "mptcp.stream" ''MbMptcpStream Nothing False)
    , ("mptcpSendKey", TsharkFieldDesc "tcp.options.mptcp.sendkey" ''MbWord64 Nothing True)
    , ("mptcpRecvKey", TsharkFieldDesc "tcp.options.mptcp.recvkey" ''MbWord64 Nothing True)
    , ("mptcpRecvToken", TsharkFieldDesc "tcp.options.mptcp.recvtok" ''MbMptcpExpectedToken Nothing True)
    -- TODO bool
    , ("mptcpDataFin", TsharkFieldDesc "tcp.options.mptcp.datafin.flag" ''MbWord64 Nothing True)
    , ("mptcpVersion", TsharkFieldDesc "tcp.options.mptcp.version" ''MbMptcpVersion Nothing True)
    , ("mptcpDack", TsharkFieldDesc "mptcp.ack" ''MbWord64 (Just "DataAck") True)
    , ("mptcpDsn", TsharkFieldDesc "mptcp.dsn" ''MbWord64 (Just "Data Sequence Number") True)

    -- these ones are experimental
    , ("relatedMappings", TsharkFieldDesc "mptcp.related_mapping" ''MbWord64 Nothing False)
    , ("reinjectionOf", TsharkFieldDesc "mptcp.reinjection_of" ''MbPacketIdList Nothing False)
    , ("reinjectedIn", TsharkFieldDesc "mptcp.reinjection_of" ''MbPacketIdList Nothing True)
    ]

-- fakeBaseFields :: FieldDescriptions
-- fakeBaseFields = [
--     ("fakePacketId", TsharkFieldDesc "frame.number" ''Word64 Nothing False)
--     , ("fakeInterfaceName", TsharkFieldDesc "frame.interface_name" ''Text Nothing False)
--     ]
-- fakeBaseFields2 :: FieldDescriptions
-- fakeBaseFields2 = prefixFields "fake_" fakeBaseFields

-- TODO
prefixFields :: Text -> FieldDescriptions -> FieldDescriptions
prefixFields prefix descs = 
  -- map (\(name, field) -> (prefix<>name , field))
  mapKeys (\name -> prefix<>name) descs

-- this should actually be host2
baseFieldsHost2 :: FieldDescriptions
baseFieldsHost2 = prefixFields "test_" baseFields


baseFieldsSender :: FieldDescriptions
baseFieldsSender = prefixFields "snd_" baseFields

baseFieldsReceiver :: FieldDescriptions
baseFieldsReceiver = prefixFields "rcv_" baseFields
