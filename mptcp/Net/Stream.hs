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

newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord)
type StreamIdTcp = StreamId Tcp
type StreamIdMptcp = StreamId Mptcp

showStream :: StreamId a -> String
showStream (StreamId a) = show a

