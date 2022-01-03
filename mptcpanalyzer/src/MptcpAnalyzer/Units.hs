{-# LANGUAGE DeriveAnyClass #-}
{-
Module:  MptcpAnalyzer.Units
Description :  Make it easier to work with units
Maintainer  : matt
Portability : Linux

ecosystem around units is not great, and we have basic needs so let's reimplement some
basic code.
-}
module MptcpAnalyzer.Units (
  -- Types
  Bytes(..)
  , Timestamp (..)
  , Throughput(..)
  , Duration(..)

  -- functions
  , diffTime
  )
where
import Data.Word (Word32, Word64)

-- import Data.Time.Units
-- import Data.Time.Units

-- https://github.com/chrissound/byteunits#readme
data Bytes = Bytes Word64

data TimeUnit = Second | MilliSecond | NanoSecond
-- TimeUnit
-- TODO pass unit
data Timestamp  = Timestamp Double deriving (Show, Eq, Ord)
data Duration = Duration Double

instance Show Duration where
  -- for now we only measure seconds
  show (Duration d) = show d ++ "s"

-- (-) :: Timestamp -> Timestamp -> Duration
diffTime :: Timestamp -> Timestamp -> Duration
diffTime (Timestamp t1) (Timestamp t2) = Duration (t1 Prelude.- t2)



data Throughput = Throughput Bytes Duration

instance Show Throughput where
  -- WIP
  show (Throughput (Bytes bytes) (Duration duration)) = show $ fromIntegral bytes / duration
