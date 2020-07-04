module Cache
where

data CacheId = CacheId {
  cacheDeps :: [FilePath]
  , cachePrefix :: String
  , cacheSuffix :: String
}

-- |Generate a cache id
-- deps -> dependencies
-- genCacheId :: [FilePath] -> CacheId
-- genCacheId deps = 



getFilenameFromCacheId :: CacheId
getFilenameFromCacheId = 
        -- self.tpl = prefix + "_".join(
        --     [os.path.basename(dep) for dep in filedeps]
        -- ) + '{hash}' + str(suffix)

class Cache m where
    put :: CacheId -> m -> Bool
    get :: CacheId -> Either m
    isValid :: CacheId -> Bool


