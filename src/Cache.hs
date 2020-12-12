{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Cache
where

import Pcap
import Data.List (intercalate)
import System.FilePath.Posix (takeBaseName)
import Control.Monad.Trans.State 
-- (StateT , put, get, evalState, evalStateT,
    -- , execStateT, runState runStateT, withStateT
    -- )
import Control.Monad.Trans.Class (lift)

data CacheId = CacheId {
  cacheDeps :: [FilePath]
  , cachePrefix :: String
  , cacheSuffix :: String
}


getFilenameFromCacheId :: CacheId -> FilePath
getFilenameFromCacheId cid =
    cachePrefix cid ++ intercalate "_" basenames ++ hash ++ cacheSuffix cid
    where
        -- takeBaseName
        basenames = map takeBaseName $ cacheDeps cid
        -- TODO
        hash = "hash"


-- TODO this should be an effect
class Monad m => Cache m where
    -- should maybe be a filepath
    putCache :: CacheId -> FilePath -> m Bool
    getCache :: CacheId -> m (Either String PcapFrame)
    isValid :: CacheId -> m Bool

-- instance MonadTrans (Cache m) where
--   -- lift :: Monad m => m a -> EitherT e m a
--   lift action = EitherT $ fmap Right $ action

instance Cache m => Cache (StateT s m) where
    putCache cid frame = do
        s <- get
        evalStateT (putCache cid frame) s
    getCache cid = do
        s <- get
        evalStateT (getCache cid) s

    isValid = lift . isValid

-- https://lexi-lambda.github.io/blog/2019/09/07/demystifying-monadbasecontrol/
-- instance Cache m => Cache (KatipContextT m) where
--     putCache = lift putCache
--     getCache cid = undefined
--     isValid = return False

instance Cache IO where
    getCache = doGetCache
    putCache = doPutCache
    isValid = isCacheValid

doGetCache :: CacheId -> IO (Either String PcapFrame)
doGetCache _cacheItemId = return $ Left "getCache not implemented yet"

doPutCache :: CacheId -> FilePath -> IO Bool
doPutCache = undefined

isCacheValid :: CacheId -> IO Bool
isCacheValid  _ = return False

