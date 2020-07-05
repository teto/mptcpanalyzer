{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Cache
where

import Pcap
import Data.List (intercalate)
import System.FilePath.Posix (takeBaseName)

data CacheId = CacheId {
  cacheDeps :: [FilePath]
  , cachePrefix :: String
  , cacheSuffix :: String
}

-- |Generate a cache id
-- deps -> dependencies
-- genCacheId :: [FilePath] -> CacheId
-- genCacheId deps = 



getFilenameFromCacheId :: CacheId -> FilePath
getFilenameFromCacheId id =
    cachePrefix id ++ intercalate "_" basenames ++ hash ++ cacheSuffix id
    where
        -- takeBaseName
        basenames = (map takeBaseName $ cacheDeps id)
        -- TODO
        hash = "hash"


class Cache m where
    putCache :: CacheId -> PcapFrame -> m Bool
    getCache :: CacheId -> Either String PcapFrame
    isValid :: CacheId -> m Bool


