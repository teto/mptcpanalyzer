{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
module Net.Stream
where
import Data.Word (Word32)
import Data.Text

-- Phantom types
data Mptcp
data Tcp
-- data Protocol = Tcp | Mptcp
-- type TcpFlagList = [TcpFlag]

-- TODO use Word instead
newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord)
type StreamIdTcp = StreamId Tcp
type StreamIdMptcp = StreamId Mptcp

showStream :: StreamId a -> Text
showStream (StreamId a) = (pack . show) a

