{-
   -}
module Tshark.Live (
  -- declarePrefixedColumns
  -- , genExplicitRecord
  -- , genRecordFrom
  -- , genRecordFromHeaders
  -- , genRecHashable
  tsharkLoop
)
where


import MptcpAnalyzer.Pcap (defaultTsharkPrefs, csvDelimiter)

import Data.Text as T
import GHC.IO.Handle
import Pipes ((>->))
import Pipes hiding (Proxy)
-- import Control.Monad.Primitive
import qualified Pipes as P
import qualified Pipes.Prelude as P
import qualified Pipes.Parse as P
import qualified Pipes.Safe as P
import Frames
import Frames.Exploration
import Frames.CSV (columnSeparator, tokenizeRow, defaultParser, pipeTableMaybeOpt, pipeTableEitherOpt)
import Control.Monad (unless, liftM)
import           Data.Vinyl.Functor             (Compose (..), (:.))
import MptcpAnalyzer.Types (Packet, HostCols)
import qualified Data.Text.Encoding as T
import qualified Data.Text.IO as T
import Control.Exception (try, IOException)


-- --         +--------+-- A 'Producer' that yields 'String's
-- --         |        |
-- --         |        |      +-- Every monad transformer has a base monad.
-- --         |        |      |   This time the base monad is 'IO'.
-- --         |        |      |  
-- --         |        |      |  +-- Every monadic action has a return value.
-- --         |        |      |  |   This action returns '()' when finished
-- --         v        v      v  v
-- stdinLn :: Producer String IO ()
-- stdinLn = do
--     eof <- lift isEOF        -- 'lift' an 'IO' action from the base monad
--     unless eof $ do
--         res <- lift getLine
--         yield res            -- 'yield' the 'String'
--         stdinLn              -- Loop

-- loop :: Effect IO ()
-- loop = for stdinLn $ \x -> do  -- Read this like: "for str in stdinLn"
--     lift $ putStrLn x

-- | Opens a file (in 'P.MonadSafe') and repeatedly applies the given
-- function to the 'Handle' to obtain lines to yield. Adapted from the
-- moribund pipes-text package.
pipeLines :: P.MonadSafe m
          => (Handle -> IO (Either IOException T.Text))
          -> Handle
          -> P.Producer T.Text m ()
pipeLines pgetLine h =
  let loop = do txt <- P.liftIO (pgetLine h)
                case txt of
                  Left _e -> return ()
                  Right y -> P.yield y >> loop
  in loop

-- | Produce lines of 'T.Text'.
-- produceTextLines :: P.MonadSafe m => FilePath -> P.Producer T.Text m ()
-- produceTextLines = pipeLines (try . T.hGetLine)


-- produceFrameChunks
-- inCoreAoS
-- --capture-comment
tsharkLoop :: Handle -> Effect IO ()
tsharkLoop hout = do
  for (tsharkProducer 0 hout) $ \x -> do
      -- (frame ::  FrameRec HostCols) <- lift ( inCoreAoS (pipeLines (try. T.hGetLine) hout  >-> pipeTableEitherOpt popts >-> P.map fromEither ))
      (frame ::  FrameRec HostCols) <- lift (inCoreAoS (P.yield x  >-> pipeTableEitherOpt popts >-> P.map fromEither ))
      -- showFrame [csvDelimiter defaultTsharkPrefs] frame
      lift $ putStrLn $ "mptcpanaluzer" ++  T.unpack x
      lift $ putStrLn $ "toto"

  where
    -- tokenize = tokenizeRow popts
    popts = defaultParser {
          columnSeparator = T.pack $ [csvDelimiter defaultTsharkPrefs]

        }
    fromEither x = case recEither x of
      Left _txt -> error ( "eitherProcessed failure : " ++ T.unpack _txt)
      Right pkt -> pkt

    recEither = rtraverse getCompose


tsharkProducer :: Int -> Handle -> Producer Text IO ()
tsharkProducer acc hout = do
  eof <- lift $ hIsEOF hout
  -- eof <- pure False
  unless eof $ do
    output <- lift $ hGetLine hout
    yield (T.pack output)
    tsharkProducer (acc+1) hout

-- for
--
-- Accept as input the different handles
readTsharkOutputAndPlotIt :: Handle -> Handle -> IO ()
readTsharkOutputAndPlotIt hout herr = do
  -- use pipeTableEitherOpt to parse 
  output <- hGetContents hout
  putStrLn output
