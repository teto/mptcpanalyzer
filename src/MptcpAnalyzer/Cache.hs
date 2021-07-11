{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE StandaloneDeriving         #-}
module MptcpAnalyzer.Cache
where

import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types

import Prelude hiding (writeFile)
import System.Directory (doesFileExist)
-- import System.Posix.Files.ByteString
import System.FilePath.Posix (takeBaseName)
import Control.Exception as CE
import Polysemy
import Data.List (intercalate)
import Frames
import Frames.CSV
import Data.Hashable
import GHC.Generics
import Data.Serialize
import Data.ByteString (writeFile)

data CacheId = CacheId {
  cacheDeps :: [FilePath]
  , cachePrefix :: String
  , cacheSuffix :: String
} deriving (Generic, Show, Eq, Hashable)

data CacheConfig = CacheConfig {
  cacheFolder :: FilePath
  , cacheEnabled :: Bool
} deriving Show

-- class Serializable a where
--   encode :: a -> String
--   decode :: String -> a

-- TODO add a cacheConfig ?
-- TODO this should be an effect
data Cache m a where
    -- should maybe be a filepath
    PutCache :: Serialize res => CacheId -> res -> Cache m Bool
    GetCache :: Serialize res => CacheId -> Cache m (Either String res)
    IsValid :: CacheId -> Cache m Bool

makeSem ''Cache

filenameFromCacheId :: CacheId -> FilePath
filenameFromCacheId cid =
    cachePrefix cid ++ intercalate "_" basenames ++ show myHash ++ cacheSuffix cid
    where
        basenames = map takeBaseName $ cacheDeps cid
        -- TODO
        -- "hash"
        myHash = hash basenames

-- Return full path to the config folder
getFullPath :: CacheConfig -> CacheId -> FilePath
getFullPath config cid = cacheFolder config ++ "/" ++ filenameFromCacheId cid


-- TODO pass cache config
runCache :: Members '[Embed IO] r => CacheConfig -> Sem (Cache : r) a -> Sem r a
runCache config = do
  interpret $ \case
      PutCache cid frame -> doPutCache config cid frame
      GetCache cid -> doGetCache config cid 
        -- return $ Left "not implemented"
        -- use config to get the final path too
        -- let csvFilename = filenameFromCacheId cid
        -- rpcap <- embed $ loadRows csvFilename
        -- return Right rpcap
      IsValid cid -> isCacheValid config cid

-- | Mock cache
--
runMockCache :: Members '[Embed IO] r => CacheConfig -> Sem (Cache : r) a -> Sem r a
runMockCache config = do
  interpret $ \case
      PutCache cid frame -> return True
      GetCache cid -> return $ Left "Not in cache"
        -- return $ Left "not implemented"
        -- use config to get the final path too
        -- let csvFilename = filenameFromCacheId cid
        -- rpcap <- embed $ loadRows csvFilename
        -- return Right rpcap
      IsValid cid -> return False

-- first check if the file exists ?
doGetCache :: (Serialize a, Members '[Embed IO] r)
  => CacheConfig
  -> CacheId
  -> Sem r (Either String a)
doGetCache config cid = return $ Left "Not implemented yet"
  -- do
  -- -- res <- embed $ loadRows csvFilename
  -- -- exists <- embed $ fileExist csvFilename
  -- res <- embed $ CE.try @IOException $ loadRows csvFilename
  -- case res of
  --   Left _excpt -> return $ Left "Exception"
  --   Right x -> return (Right x)
  -- where
  --     csvFilename = getFullPath config cid


-- TODO reuse export function ?
doPutCache :: (Serialize a, Members '[Embed IO] r)
  => CacheConfig -> CacheId -> a -> Sem r Bool
doPutCache config cid resource =
  -- writeFile
  -- writeCSV :: (ColumnHeaders ts, Foldable f, RecordToList ts, RecMapMethod ShowCSV ElField ts) => FilePath -> f (Record ts) -> IO ()
  -- produceDSV
  -- embed $ writeCSV csvFilename frame >> return True
  embed $ do
    writeFile csvFilename $ encode resource
    return True
  where
      csvFilename = getFullPath config cid


-- TODO log ? / compare inputs date
isCacheValid :: Members '[Embed IO] r => CacheConfig -> CacheId -> Sem r Bool
isCacheValid config cid =
  embed $ doesFileExist filename
  where
    filename = getFullPath config cid
