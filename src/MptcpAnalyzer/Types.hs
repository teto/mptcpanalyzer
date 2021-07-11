{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE DerivingVia         #-}
{-# LANGUAGE FlexibleInstances                      #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE PackageImports         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Types
where

-- Inspired by Frames/demo/missingData
import MptcpAnalyzer.Stream
import Tshark.TH
import Tshark.Fields
import "mptcp-pm" Net.Tcp (TcpFlag(..))
import Net.Bitset (fromBitMask, toBitMask)
import Net.IP
import Net.IPv6 (IPv6(..))
import Net.Tcp
import Net.Mptcp

import Data.Hashable
import qualified Data.Hashable as Hash
import Data.Monoid (First(..))
import Data.Vinyl (Rec(..), ElField(..), rapply, xrec, rmapX)
import qualified Data.Vinyl.TypeLevel as V
import Data.Vinyl.Functor (Compose(..), (:.))
import Data.Vinyl.Class.Method

import qualified Data.Vinyl as V
import Data.Word (Word8, Word16, Word32, Word64)
import Data.WideWord.Word128
import Control.Monad (liftM)
import Frames
import Frames.ShowCSV
import Frames.TH
import Frames.CSV (QuotingMode(..), ParserOptions(..))
-- (Parseable(..), parseIntish, Parsed(..))
import Frames.ColumnTypeable
import Data.Text (Text)
import qualified Data.Text as T
import qualified Text.Read as T
import Frames.InCore (VectorFor)
import qualified Data.Vector as V
import Numeric (readHex)
import Language.Haskell.TH
-- import GHC.TypeLits
import qualified Data.Text.Lazy.Builder as B
import Data.Typeable (Typeable)
import Control.Lens
import Control.Monad (MonadPlus, mzero)
import qualified Frames as F
import qualified Data.Set as Set
import qualified Data.Text as TS
import Options.Applicative
import GHC.Generics
import GHC.TypeLits (KnownSymbol)
import MptcpAnalyzer.ArtificialFields

{- Describe a TCP connection, possibly an Mptcp subflow
  The equality implementation ignores several fields
-}
-- data TcpConnection = TcpConnection {
--   -- TODO use libraries to deal with that ? filter from the command line for instance ?
--   srcIp :: IP -- ^Source ip
--   , dstIp :: IP -- ^Destination ip
--   , srcPort :: Word16  -- ^ Source port
--   , dstPort :: Word16  -- ^Destination port
--   , priority :: Maybe Word8 -- ^subflow priority
--   , localId :: Word8  -- ^ Convert to AddressFamily
--   , remoteId :: Word8
--   -- TODO remove could be deduced from srcIp / dstIp ?
--   , subflowInterface :: Maybe Word32 -- ^Interface of Maybe ? why a maybe ?
--   -- add TcpMetrics member
--   -- , tcpMetrics :: Maybe [SockDiagExtension]  -- ^Metrics retrieved from kernel

-- } deriving (Show, Generic, Ord)


declarePrefixedColumns "" baseFields

-- when loading the second pcap to merge, we need to distinguish between the different fields
-- declarePrefixedColumns "test" baseFields
declarePrefixedColumns "" baseFieldsHost2
declarePrefixedColumns "" baseFieldsSender
declarePrefixedColumns "" baseFieldsReceiver

-- todo declare it from ArtificialFields ?
-- artificial types, i.e. created by the app and not tshark
declareColumn "tcpDest" ''ConnectionRole
-- | True if host 1 is sender
declareColumn "senderHost" ''Bool
declareColumn "senderDest" ''ConnectionRole
declareColumn "mptcpDest" ''ConnectionRole
declareColumn "packetHash" ''Int
declareColumn "colOwd" ''Double


-- TODO check it generates
-- HostCols
genRecordFrom "HostCols" baseFields
-- these are useful when merging different
genRecordFromHeaders "" "HostColsPrefixed" baseFieldsHost2
-- genExplicitRecord "test" "HostColsPrefixed" baseFieldsHost2
genRecHashable "HashablePart" baseFields
genRecordFrom "SenderCols" baseFieldsSender
genRecordFrom "ReceiverCols" baseFieldsReceiver

-- | Represent a mapping between 2 pcaps captured at either end of a connection
-- (i.e., one pcap was captured at the client, the other at the receiver)
data PcapMapping a = PcapMapping {
      -- | Host 1 pcap to load
      pmapPcap1 :: FilePath
      , pmapStream1 :: StreamId a
      -- | Host 2 
      , pmapPcap2 :: FilePath
      , pmapStream2 :: StreamId a
      -- , pmapVerbose :: Bool
      -- , pmapLimit :: Int -- ^Number of comparisons to show
      -- , pmapMptcp :: Bool -- ^Wether it's an MPTCP
    }


-- row / ManRow
type Packet = Record HostCols
type PacketWithSenderDest = Record (SenderDest ': HostCols)
type PacketWithTcpDest = Record (TcpDest ': HostCols)
-- type PacketWithMptcpDest = Record (MptcpDest ': MptcpDest ': HostCols)

-- https://stackoverflow.com/questions/14020491/is-there-a-way-of-deriving-binary-instances-for-vinyl-record-types-using-derive?rq=1
-- forall t s a rs. (t ~ '(s,a)
-- comparable to Storable
deriving instance  (KnownSymbol s, Hashable a) => Hashable(ElField '(s, a))
deriving instance Hashable TcpFlag

-- | This is only here so we can use hash maps for the grouping step.  This should properly be in Vinyl itself.
instance Hashable (F.Record '[]) where
  hash = const 0
  {-# INLINABLE hash #-}
  hashWithSalt s = const s
  {-# INLINABLE hashWithSalt #-}

instance (V.KnownField t, Hashable (V.Snd t), Hashable (F.Record rs), rs F.⊆ (t ': rs)) => Hashable (F.Record (t ': rs)) where
  hashWithSalt s r = s `Hash.hashWithSalt` (F.rgetField @t r) `Hash.hashWithSalt` F.rcast @rs r
  {-# INLINABLE hashWithSalt #-}

deriving instance Hashable IP

-- IPv6 is Word128
deriving instance Generic IPv6

deriving instance Hashable Word128
deriving instance Hashable IPv6

-- shadow param
-- @a@ be Tcp / Mptcp
-- @b@ could be the direction
type PcapFrame a = Frame Packet


tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show
-- TODO PcapFrame should be a monoid and a semigroup with a list of Connection []


-- | TODO adapt / rename to AFrame ? AdvancedFrames ?
-- GADT ?
data FrameFiltered a rs = FrameTcp {
    ffCon :: a
    -- StreamConnection b => b
    -- Frame of sthg maybe even bigger with TcpDest / MptcpDest
    , ffFrame :: Frame rs
  }

aframeLength :: FrameFiltered a rs -> Int
aframeLength = frameLength . ffFrame

-- data FrameMerged = FrameMerged {
--     ffCon :: !Connection

--   }
  -- FrameSubflow {
  --   ffCon :: !MptcpSubflow
  --   , ffFrame :: Frame a

-- https://stackoverflow.com/questions/52299478/pattern-match-phantom-type
-- data AFrame (p :: Protocol) where
-- AFrame :: SStreamId p -> Word32 -> AFrame p


-- Helper to pass information across functions
data MyState = MyState {
  _stateCacheFolder :: FilePath
  , _loadedFile   :: Maybe (FrameRec HostCols)  -- ^ cached loaded pcap
  , _prompt   :: String  -- ^ cached loaded pcap
}

makeLenses ''MyState



type OptionList = T.Text


-- Used to parse tokens
instance (Read a, Typeable a, Frames.ColumnTypeable.Parseable a) => Frames.ColumnTypeable.Parseable (Maybe a) where
  parse txt = case T.null txt of
    True -> return $ Definitely Nothing
    False -> do
      val2 <- val
      return $ case val2 of
        Possibly x -> Possibly (Just x)
        Definitely x -> Definitely (Just x)
    where
      val :: MonadPlus m => m (Parsed a)
      val = parse txt

      -- val2 :: MonadPlus m => m (Parsed (Maybe a))
      -- val2 = Just <$> val
    -- case w64 of
    --   Left msg -> error $ "could not read " ++ show txt ++ ", error: " ++ msg
    --   Right val -> Definitely (Just val)
    -- where
    --     w64 = T.readEither (T.unpack txt)


-- TODO parse based on ,
-- instance Frames.ColumnTypeable.Parseable (Maybe OptionList) where
--   parse _ = return $ Definitely Nothing

instance Frames.ColumnTypeable.Parseable Word16 where
  parse = parseIntish
instance Frames.ColumnTypeable.Parseable Word32 where
  parse = parseIntish

instance Frames.ColumnTypeable.Parseable Word64 where
  parse = parseIntish

instance Frames.ColumnTypeable.Parseable IP where
  -- parse :: MonadPlus m => T.Text -> m (Parsed a)
-- IP.decode :: Text -> Maybe IP
  -- fmap Definitely
  parse text = case decode text of
    Nothing -> return $ Possibly $ ipv4 0 0 0 0
    Just ip -> return $ Definitely ip

-- instance Frames.ColumnTypeable.Parseable Word64 where
--   parse = parseIntish

instance Readable (StreamId a) where
  fromText t = case T.readMaybe (T.unpack t) of
      Just streamId -> return $ StreamId streamId
      Nothing -> mzero


instance Frames.ColumnTypeable.Parseable (StreamId Mptcp) where
  parse = parseIntish

instance Frames.ColumnTypeable.Parseable (StreamId Tcp) where
  parse = parseIntish


-- 
parseList :: (MonadPlus m, Typeable a, Frames.ColumnTypeable.Parseable a) => Text -> m (Parsed [a])
parseList text = fmap Definitely (mapM parse' (T.splitOn "," text))

instance Frames.ColumnTypeable.Parseable [Word64] where
  -- expected type parse :: MonadPlus m => T.Text -> m (Parsed [a])
  parse = parseList


-- could not parse 0x00000002
-- strip leading 0x
instance Frames.ColumnTypeable.Parseable [TcpFlag] where
  parse text = case readHex (T.unpack $ T.drop 2 text) of
    -- TODO generate
    [(n, "")] -> return $ Definitely $ fromBitMask n
    _ -> error $ "TcpFlags: could not parse " ++ T.unpack text

-- TODO rewrite it as wireshark exposes it, eg, in hexa ?
-- instance ShowCSV [TcpFlag] where
--   -- showCSV :: a -> Text
--   showCSV flagList = T.concat texts
--     where
--       texts = map (T.pack . show .fromEnum) flagList
--       res = toBitMask flagList

instance ShowCSV [TcpFlag] where
  -- showCSV :: a -> Text
  showCSV flagList = T.concat texts
    where
      texts = map (T.pack . show .fromEnum) flagList
      res = toBitMask flagList

instance ShowCSV [Word64] where
  -- showCSV :: a -> Text
  showCSV seqs = T.intercalate "," texts
    where
      texts = map (T.pack . show .fromEnum) seqs

instance ShowCSV IP where
  showCSV = encode

instance ShowCSV Word16 where
instance ShowCSV Word32 where
instance ShowCSV Word64 where
instance ShowCSV m => ShowCSV (Maybe m) where
  showCSV = \case
    Nothing -> ""
    Just x -> showCSV x

--
instance ShowCSV (StreamId a) where
  showCSV (StreamId stream) = showCSV stream


-- type ManMaybe = Rec (Maybe :. ElField) ManColumns
-- TODO goal here is to choose the most performant Data.Vector
type instance VectorFor Word16 = V.Vector
type instance VectorFor Word32 = V.Vector
type instance VectorFor Word64 = V.Vector
type instance VectorFor (Maybe Word16) = V.Vector
type instance VectorFor (Maybe Word32) = V.Vector
type instance VectorFor (Maybe Word64) = V.Vector
type instance VectorFor IP = V.Vector
type instance VectorFor TcpFlagList = V.Vector
type instance VectorFor (StreamId a) = V.Vector

type instance VectorFor (Maybe Int) = V.Vector
type instance VectorFor (Maybe Bool) = V.Vector
type instance VectorFor (Maybe OptionList) = V.Vector
type instance VectorFor MbMptcpStream = V.Vector
type instance VectorFor ConnectionRole = V.Vector
-- FIX generalize
type instance VectorFor [Word64] = V.Vector
type instance VectorFor (Maybe [Word64]) = V.Vector

-- type instance VectorFor MbTcpStream = V.Vector

-- getHeaders :: [(T.Text, TsharkFieldDesc)] -> [(T.Text, Q Type)]
-- getHeaders = map (\(name, x) -> (name, colType x))

-- headersFromFields :: [(T.Text, TsharkFieldDesc)] -> Q [(T.Text, Q Type)]
-- headersFromFields fields = do
--   pure (getHeaders fields)


