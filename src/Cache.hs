{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Cache
where

import Pcap
import Data.List (intercalate)
import System.FilePath.Posix (takeBaseName)
import Control.Monad.Reader (MonadReader)
import Control.Monad.Trans.State (State, StateT, put, get, evalState,
        execStateT, runState, evalStateT, runStateT, withStateT)
import Control.Monad.Trans.Class (lift)
import Katip

data CacheId = CacheId {
  cacheDeps :: [FilePath]
  , cachePrefix :: String
  , cacheSuffix :: String
}

-- data Cache = Cache {

-- }
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


class Monad m => Cache m where
    putCache :: CacheId -> PcapFrame -> m Bool
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
