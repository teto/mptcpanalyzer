-- copy/pasted from https://github.com/adamConnerSax/Frames-utils
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE DerivingVia         #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PolyKinds           #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE TypeOperators       #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE UndecidableInstances #-}
module MptcpAnalyzer.Frames.Utils
where

import qualified Data.Foldable                 as F
import qualified Frames as F
import qualified Frames.Melt                   as F

import qualified Data.Vinyl                    as V
import qualified Data.Vinyl.TypeLevel          as V
import qualified Data.Vinyl.XRec               as V
import           Frames.Melt          (RDeleteAll, ElemOf)

import           GHC.TypeLits         (KnownSymbol, Symbol)

import qualified Data.Text            as T
import qualified Data.Vinyl           as V
import qualified Data.Vinyl.Curry     as V
import qualified Data.Vinyl.Functor   as V
import           Data.Vinyl.TypeLevel as V --(type (++), Snd)
import qualified Frames               as F
import           Frames.Melt          (RDeleteAll, ElemOf)

import           GHC.TypeLits         (KnownSymbol, Symbol)
import Data.Kind (Type)

-- |  change a column "name" at the type level
retypeColumn :: forall x y rs. ( V.KnownField x
                               , V.KnownField y
                               , V.Snd x ~ V.Snd y
                               , ElemOf rs x
                               , F.RDelete x rs F.⊆ rs
--                               , Rename (Fst x) (Fst y) rs ~ (RDelete '(Fst x, Snd y) rs ++ '[ '(Fst y, Snd y)]))
                               )
  => F.Record rs -> F.Record (F.RDelete x rs V.++ '[y])
retypeColumn = transform @rs @'[x] @'[y] (\r -> F.rgetField @x r F.&: V.RNil)

-- | replace subset with a calculated different set of fields
transform :: forall rs as bs. (as F.⊆ rs, RDeleteAll as rs F.⊆ rs)
             => (F.Record as -> F.Record bs) -> F.Record rs -> F.Record (RDeleteAll as rs V.++ bs)
transform f xs = F.rcast @(RDeleteAll as rs) xs `F.rappend` f (F.rcast xs)


-- TODO: replace all of the renaming with this.  But it will add contraints everywhere (and remove a bunch and I've not time right now! -}
{- From a vinyl PR.  This way os better -}
-- | @Rename old new fields@ replaces the first occurence of the
-- field label @old@ with @new@ in a list of @fields@. Used by
-- 'rename'.
type family Rename old new ts where
  Rename old new '[] = '[]
  Rename old new ('(old,x) ': xs) = '(new,x) ': xs
  Rename old new ('(s,x) ': xs) = '(s,x) ': Rename old new xs

{-
-- | Replace a field label. Example:
--
-- @rename \@"name" \@"handle" (fieldRec (#name =: "Joe", #age =: (40::Int)))
rename :: forall old new ts. V.Rec V.ElField ts -> V.Rec V.ElField (Rename old new ts)
rename = unsafeCoerce
-}

-- take a type-level-list of (fromName, toName, type) and use it to rename columns in suitably typed record
type family FromRecList (a :: [(Symbol, Symbol, Type)]) :: [(Symbol, Type)] where
  FromRecList '[] = '[]
  FromRecList ('(fs, ts, t) ': rs) = '(fs, t) ': FromRecList rs

type family ToRecList (a :: [(Symbol, Symbol, Type)]) :: [(Symbol, Type)] where
  ToRecList '[] = '[]
  ToRecList ('(fs, ts, t) ': rs) = '(ts, t) ': ToRecList rs

class (FromRecList cs F.⊆ rs) => RetypeColumns (cs :: [(Symbol, Symbol, Type)]) (rs :: [(Symbol, Type)]) where
  retypeColumns :: (rs ~ (rs V.++ '[])) => F.Record rs -> F.Record (RDeleteAll (FromRecList cs) rs V.++ ToRecList cs)

instance RetypeColumns '[] rs where
  retypeColumns = id

instance (RetypeColumns cs rs
         , V.KnownField '(fs, t)
         , V.KnownField '(ts, t)
         , ElemOf rs '(fs, t)
         , (RDelete '(fs, t) (RDeleteAll (FromRecList cs) rs V.++ ToRecList cs) V.++ '[ '(ts, t)])
         ~ (RDeleteAll (FromRecList cs) (RDelete '(fs, t) rs) V.++ ('(ts, t) ': ToRecList cs))
         , ElemOf (RDeleteAll (FromRecList cs) rs ++ ToRecList cs) '(fs, t)
         , RDelete '(fs, t) (RDeleteAll (FromRecList cs) rs ++ ToRecList cs) F.⊆ (RDeleteAll (FromRecList cs) rs ++ ToRecList cs)
         , Rename fs ts (RDeleteAll (FromRecList cs) rs ++ ToRecList cs) ~ (RDeleteAll (FromRecList cs) (RDelete '(fs, t) rs) ++ ('(ts, t) : ToRecList cs))
         )
    => RetypeColumns ('(fs, ts, t) ': cs) rs where
  retypeColumns = retypeColumn @'(fs, t) @'(ts, t) @(RDeleteAll (FromRecList cs) rs V.++ ToRecList cs)  . retypeColumns @cs @rs

{-
-- take a type-level-list of (fromName, toName, type -> type) and use it to transform columns in suitably typed record
type family FromTList (a :: [(Symbol, Symbol, Type -> Type)]) :: [(Symbol, Type)] where
  FromRecList '[] = '[]
  FromRecList ('(fs, ts, x -> y) ': rs) = '(fs, x) ': FromRecList rs

type family ToTList (a :: [(Symbol, Symbol, Type -> Type)]) :: [(Symbol, Type)] where
  ToRecList '[] = '[]
  ToRecList ('(fs, ts, x -> y) ': rs) = '(ts, y) ': ToRecList rs  
  
class (FromRecList cs F.⊆ rs) => RetypeColumns (cs :: [(Symbol, Symbol, Type -> Type)]) (rs :: [(Symbol, Type)]) where
  retypeColumns :: (rs ~ (rs V.++ '[])) => F.Record rs -> F.Record (RDeleteAll (FromRecList cs) rs V.++ (ToRecList cs))

instance TransformColumns '[] rs where
  retypeColumns = id

instance (RetypeColumns cs rs
         )
    => RetypeColumns ('(fs, ts, t) ': cs) rs where
  retypeColumns = retypeColumn @'(fs, t) @'(ts, t) @(RDeleteAll (FromRecList cs) rs V.++ (ToRecList cs))  . retypeColumns @cs @rs
-}


