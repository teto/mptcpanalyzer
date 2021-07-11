{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Plots.Owd
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.Plots.Types
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Debug

import Prelude hiding (filter, lookup, repeat, log)
import Options.Applicative
import Polysemy
import Frames
import Frames.CSV

-- import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
-- import Graphics.Rendering.Chart.Easy

import Graphics.Rendering.Chart.Easy hiding (argument)
import Graphics.Rendering.Chart.Backend.Cairo
import Data.Word (Word8, Word16, Word32, Word64)

import Data.Text (Text)
import qualified Data.Text as T
import qualified Pipes as P
import qualified Pipes.Prelude as P
import Polysemy
-- import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
-- import Colog.Polysemy (Log, log)
import System.Process hiding (runCommand)
import System.Exit
-- import Data.Time.LocalTime
import Data.Foldable (toList)
import Data.Maybe (fromMaybe)
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Directory (renameFile)
import System.IO (Handle)
import Frames.ShowCSV (showCSV)
import qualified Data.Set as Set
import Debug.Trace



-- | A typeclass abstracting the functions we need
-- to be able to plot against an axis of type a
-- class Ord a => PlotValue a where
--     toValue  :: a -> Double
--     fromValue:: Double -> a
--     autoAxis :: AxisFn a

-- instance RealFloat Word32 where

instance PlotValue Word32 where
    toValue  = fromIntegral
    fromValue = truncate . toRational
        -- autoAxis = autoScaledAxis def
    -- autoScaledAxis def
    -- autoAxis = autoScaledIntAxis def
    autoAxis   = autoScaledIntAxis defaultIntAxis


