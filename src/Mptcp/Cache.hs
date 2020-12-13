{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Mptcp.Cache
where

import Pcap
import Data.List (intercalate)
import System.FilePath.Posix (takeBaseName)
-- import Control.Monad.Trans.State 
-- (StateT , put, get, evalState, evalStateT,
    -- , execStateT, runState runStateT, withStateT
    -- )
-- import Control.Monad.Trans.Class (lift)

import Polysemy

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
data Cache m a where
    -- should maybe be a filepath
    PutCache :: CacheId -> FilePath -> Cache m Bool
    GetCache :: CacheId -> Cache m (Either String PcapFrame)
    IsValid :: CacheId -> Cache m Bool

makeSem ''Cache

-- instance MonadTrans (Cache m) where
--   -- lift :: Monad m => m a -> EitherT e m a
--   lift action = EitherT $ fmap Right $ action

-- instance Cache m => Cache (StateT s m) where
--     putCache cid frame = do
--         s <- get
--         evalStateT (putCache cid frame) s
--     getCache cid = do
--         s <- get
--         evalStateT (getCache cid) s
--     isValid = lift . isValid

-- https://lexi-lambda.github.io/blog/2019/09/07/demystifying-monadbasecontrol/
-- instance Cache m => Cache (KatipContextT m) where
--     putCache = lift putCache
--     getCache cid = undefined
--     isValid = return False

-- instance Cache IO where
--     getCache = doGetCache
--     putCache = doPutCache
--     isValid = isCacheValid

cacheToIO :: Sem (Cache : r) a -> Sem r a
cacheToIO = interpret $ \case
  PutCache cid fp -> doPutCache cid fp
  GetCache cid -> doGetCache cid
  IsValid cid -> isCacheValid cid

doGetCache :: CacheId -> Sem r (Either String PcapFrame)
doGetCache _cacheItemId = return $ Left "getCache not implemented yet"

doPutCache :: CacheId -> FilePath -> Sem r Bool
doPutCache = undefined

isCacheValid :: CacheId -> Sem r Bool
isCacheValid  _ = return False

