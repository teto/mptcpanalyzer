-- TODO reexport stuff ?
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances #-}
module MptcpAnalyzer.Frame
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.Pcap (defaultParserOptions)

import Data.Serialize
import Data.Text as T
import Data.Text.Encoding as TSE
import Data.ByteString as BS
import Data.ByteString.Lazy as LBS
import Data.ByteString.Lazy.UTF8 as BLU
import Pipes ((>->))
import qualified Pipes as P
import qualified Pipes.Prelude as P
import qualified Pipes.Parse as P
import qualified Pipes.Safe as P
import qualified Pipes.Safe.Prelude as Safe
import System.IO (Handle, IOMode(ReadMode, WriteMode))
import Data.Vinyl hiding (rget)
import Frames
import Frames.CSV hiding (consumeTextLines)
import Frames.ShowCSV
-- import Data.Proxy
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.Vinyl as V
import qualified Data.Vinyl.Class.Method as V


-- convertToBs :: Frame (Record a) -> Put
-- convertToBs f = do
--       bs <- P.runSafeT . P.runEffect $ produceDSV defaultParserOptions f >-> P.map BLU.fromString
--       return bs

newtype Test a = FrameRec a

-- TODO here we want to put a bytestring
instance (ColumnHeaders rs, V.RecMapMethod Show ElField rs, V.RecordToList rs) => Serialize (Frame (Record rs)) where
  -- 
  -- putByteString
  
  put f = do
      -- (csvDelimiter defaultTsharkPrefs)
      let bs = BLU.fromString $ showFrame "|" f
      -- let bs = unsafePerformIO $ do
      --         writeDSV defaultParserOptions tmpFile f
      --         BS.readFile tmpFile
      -- renvoie unit IO ()
      putByteString $ LBS.toStrict bs
      -- where
      --   tmpFile = "tmp.csv"

  -- put f = undefined
  get = undefined

consumeTextLines :: P.MonadSafe m => FilePath -> P.Consumer BS.ByteString m r
consumeTextLines fp = Safe.withFile fp WriteMode $ \h ->
  let loop = P.await >>= P.liftIO . BS.hPut h >> loop
  in loop

-- | Write a header row with column names followed by a line of text
-- for each 'Record' to the given file.
-- doWriteDSV:: (ColumnHeaders ts, Foldable f, RecordToList ts,
--              RecMapMethod ShowCSV ElField ts)
--          => ParserOptions -> FilePath -> f (Record ts) -> IO ()
-- doWriteDSV opts fp recs = P.runSafeT . P.runEffect $
--                    produceDSV opts recs >-> P.map (TSE.encodeUtf8 . T.pack) >-> consumeTextLines fp

