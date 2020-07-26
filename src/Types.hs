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
module Types
-- (
--     )
where


import Frames.InCore (VectorFor)
import Net.IP
type instance VectorFor IP = V.Vector

instance Readable IP  where
  fromText t = case decode t of
      Just ip -> return ip
      Nothing -> mzero

type MyColumns = IP ': CommonColumns

