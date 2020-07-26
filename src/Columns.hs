{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE FlexibleInstances                      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE FlexibleContexts, QuasiQuotes #-}
module Columns
where

import Control.Monad (mzero)
import Frames (CommonColumns, Readable(..))
-- import Frames.ColumnTypeable (Parseable(..))
import Frames.InCore (VectorFor)
import Net.IP
import qualified Data.Vector as V

type instance VectorFor IP = V.Vector

-- instance Parseable IP where
--   parse = fmap (fmap Chicago) . parse


instance Readable IP  where
  fromText t = case decode t of
      Just ip -> return ip
      Nothing -> mzero


