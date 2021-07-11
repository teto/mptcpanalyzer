{-# LANGUAGE DerivingVia         #-}
{-# LANGUAGE DerivingStrategies         #-}
module MptcpAnalyzer.Stream
where
import Data.Word (Word32)
import Data.Hashable
import Options.Applicative

-- Phantom types
data Mptcp
data Tcp
-- data Protocol = Tcp | Mptcp
-- type TcpFlagList = [TcpFlag]

-- TODO use Word instead
newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord ) deriving Hashable via Word32
type StreamIdTcp = StreamId Tcp
type StreamIdMptcp = StreamId Mptcp

-- showStream :: StreamId a -> Text


-- |Can load stream ids from CSV files
readStreamId :: ReadM (StreamId a)
readStreamId = eitherReader $ \arg -> case reads arg of
  [(r, "")] -> return $ StreamId r
  _ -> Left $ "readStreamId: cannot parse value `" ++ arg ++ "`"
