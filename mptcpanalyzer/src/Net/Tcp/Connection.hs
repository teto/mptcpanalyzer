{-# LANGUAGE OverloadedStrings #-}

module Net.Tcp.Connection (
    TcpConnection(..)
  , TcpConnectionOriented(..)
  , showTcpConnectionText
)
where
import Data.Text as TS
import Data.Word (Word16, Word32, Word64, Word8)
import MptcpAnalyzer.Stream
import Net.IP

-- | Identifies a TCP connection
data TcpConnection = TcpConnection {
  -- TODO use libraries to deal with that ? filter from the command line for instance ?
    conTcpClientIp :: IP -- ^Client ip
  , conTcpServerIp :: IP -- ^Server ip
  , conTcpClientPort :: Word16  -- ^ Source port
  , conTcpServerPort :: Word16  -- ^Destination port
  , conTcpStreamId :: StreamIdTcp -- ^ @tcp.stream@ in wireshark
  } deriving (Show, Eq, Ord)


-- |
data TcpConnectionOriented = TcpConnectionOriented {
    conTcpSourceIp :: IP -- ^Source ip
  , conTcpDestinationIp :: IP -- ^Destination ip
  , conTcpSourcePort :: Word16  -- ^ Source port
  , conTcpDestinationPort :: Word16  -- ^Destination port
  , conTcpStreamId2 :: StreamIdTcp -- ^ @tcp.stream@ in wireshark
  } deriving (Show, Eq, Ord)


-- tcpConnectionfromOriented ::
--      TcpConnectionOriented
--   -> Bool
--   -- ^ Source is the client
--   -> TcpConnection
-- tcpConnectionfromOriented =


tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show

-- | Pretty print
showTcpConnectionText :: TcpConnection -> Text
showTcpConnectionText con =
  showIp (conTcpClientIp con) <> ":" <> tshow (conTcpClientPort con) <> " -> "
      <> showIp (conTcpServerIp con) <> ":" <> tshow (conTcpServerPort con)
      <> " (tcp.stream: " <> showStream (conTcpStreamId con) <> ")"
  where
    showIp = Net.IP.encode
    showStream (StreamId a) = tshow a
