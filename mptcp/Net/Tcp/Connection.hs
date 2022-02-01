{-# LANGUAGE OverloadedStrings #-}
{-
Module:  Net.Tcp.Connection
Description : Describes
Maintainer  : matt
Portability : Linux


-}

module Net.Tcp.Connection (
    TcpConnection(..)
  , TcpConnectionOriented(..)
  , tcpConnectionToOriented
  , showTcpConnectionText
  , reverseTcpConnectionTuple
  , tcpConnectionFromOriented
)
where
import Data.Text as TS
import Data.Word (Word16, Word32, Word64, Word8)
import Net.Stream
import Net.IP

-- | Identifies a TCP connection
data TcpConnection = TcpConnection {
    conTcpClientIp :: IP -- ^Client ip
  , conTcpServerIp :: IP -- ^Server ip
  , conTcpClientPort :: Word16  -- ^Client port
  , conTcpServerPort :: Word16  -- ^Server port
  , conTcpStreamId :: StreamIdTcp -- ^ @tcp.stream@ in wireshark
  } deriving (Show, Eq)

instance Ord TcpConnection where
  con1 `compare` con2 = (conTcpStreamId con1) `compare` (conTcpStreamId con2)

-- | Used when you can't identify the server or client yet.
-- See "tcpConnectionFromOriented"/"tcpConnectionToOriented"
data TcpConnectionOriented = TcpConnectionOriented {
    conTcpSourceIp :: IP -- ^Source ip
  , conTcpDestinationIp :: IP -- ^Destination ip
  , conTcpSourcePort :: Word16  -- ^ Source port
  , conTcpDestinationPort :: Word16  -- ^Destination port
  } deriving (Show, Eq, Ord)


reverseTcpConnectionTuple :: TcpConnectionOriented -> TcpConnectionOriented
reverseTcpConnectionTuple con = TcpConnectionOriented {
    conTcpSourceIp = conTcpDestinationIp con
  , conTcpDestinationIp = conTcpSourceIp con
  , conTcpSourcePort = conTcpDestinationPort con
  , conTcpDestinationPort = conTcpSourcePort con
  }


-- | Uses the source as client. Use 'reverseTcpConnectionTuple' to assign the server as source
tcpConnectionFromOriented ::
     TcpConnectionOriented
  -- ^ Source is the client
  -> TcpConnection
tcpConnectionFromOriented tup = TcpConnection {
    conTcpClientIp = conTcpSourceIp tup
  , conTcpServerIp = conTcpDestinationIp tup
  , conTcpClientPort = conTcpSourcePort tup
  , conTcpServerPort = conTcpDestinationPort tup
  , conTcpStreamId = StreamId 0
  }

tcpConnectionToOriented ::
     TcpConnection
  -- ^ Source is the client
  -> TcpConnectionOriented
tcpConnectionToOriented con = TcpConnectionOriented {

    conTcpSourceIp = conTcpClientIp con
  , conTcpDestinationIp = conTcpServerIp con
  , conTcpSourcePort = conTcpClientPort con
  , conTcpDestinationPort = conTcpServerPort con
  }

tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show

-- | Pretty print
showTcpConnectionText :: TcpConnection -> Text
showTcpConnectionText con =
  showIp (conTcpClientIp con) <> ":" <> tshow (conTcpClientPort con) <> " -> "
      <> showIp (conTcpServerIp con) <> ":" <> tshow (conTcpServerPort con)
      <> " (tcp.stream: " <> (TS.pack . showStream) (conTcpStreamId con) <> ")"
  where
    showIp = Net.IP.encode
