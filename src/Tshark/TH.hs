{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell            #-}
module Tshark.TH
where

import Tshark.Fields
-- import MptcpAnalyzer.Types

import qualified Data.Text as T
import Language.Haskell.TH
import Language.Haskell.TH.Syntax (Q)
import GHC.TypeLits
import Net.IP
import Control.Arrow (second, first)
import Data.Word (Word16, Word32, Word64)
-- import Language.Haskell.TH.Syntax
import Data.Vinyl ()
-- sequenceQ
-- sequenceQ
import Language.Haskell.TH.Syntax (sequenceQ, Q)
-- for ( (:->)())
import Frames.Col ()
-- ((:->))
import Frames
import Frames.TH hiding (tablePrefix, rowTypeName)
-- import Frames
import Frames.Utils
import Data.Proxy (Proxy(..))
import Control.Monad (foldM)
import Data.Char (toLower)
import Data.Map (mapWithKey, toList)
import qualified Data.Map as Map


-- WARN the behavior here differs from Frames
declarePrefixedColumns :: Text -> FieldDescriptions -> DecsQ
declarePrefixedColumns prefix fields = do
  foldM toto (mempty) (toList fields)
  where
    -- acc ++
    toto acc (colName, field) = do
      -- Note: Frames.declarePrefixedColumn doesn't prefix the colName but the accessors !
      -- expects colName lensPrefix type
      t <- declarePrefixedColumn (prefix <> colName) prefix (tfieldColType field)
      return $ acc ++ t

-- TODO search frames.TH
-- Generates a '[ ]
-- la solution est dans tableTypesText'
-- Generate a FieldRec
-- TODO rename
genRecordFrom :: String -> FieldDescriptions -> DecsQ
genRecordFrom  = genRecordFromHeaders ""

-- rename to explicit / upstream
-- ici on presuppose que les colonnes existrent deja en fait ?
genRecordFromHeaders :: String -> String -> FieldDescriptions -> DecsQ
genRecordFromHeaders tablePrefix rowTypeName fields = genExplicitRecord tablePrefix rowTypeName converted
  where
    converted = map (\(name, field) -> (name, tfieldColType field)) (toList fields)

-- mergedFields :: [(String, Name)]
-- FieldDescriptions
-- tablePrefix here consists in the lenses but not the actual column names
genExplicitRecord :: String -> String -> [(Text, Name)] -> Q [Dec]
genExplicitRecord tablePrefix rowTypeName fields = do
  (colTypes, colDecs) <- (second concat . unzip)
                        <$> mapM (uncurry mkColDecs) headers
  -- let recTy = TySynD (mkName rowTypeName) [] (recDec colTypes)
  let recTy = TySynD (mkName rowTypeName) [] (qqDec colTypes)
  return [recTy]
  where
    -- colTypes = map (\(name, field) -> (name, colType field)) fields
    -- TODO headers
    -- headers :: [(Text, Type)]
    headers = zip colNames (repeat (ConT ''T.Text))
    -- colNames :: [Text]
    colNames = map fst fields
    mkColDecs colNm colTy = do
      let safeName = T.unpack (sanitizeTypeName colNm)
      mColNm <- lookupTypeName (tablePrefix ++ safeName)
      case mColNm of
        Just n -> pure (ConT n, [])
        Nothing -> colDec (T.pack tablePrefix) rowTypeName colNm (Right colTy)


genRecHashable :: String -> FieldDescriptions -> DecsQ
genRecHashable prefix fields = genRecordFrom prefix (Map.filter (tfieldHashable  ) fields)

-- inspired from recDec
qqDec :: [Type] -> Type
qqDec = go
  where go [] = PromotedNilT
        go (t:cs) = AppT (AppT PromotedConsT t) (go cs)

-- TODO make public in Frames
-- table
-- mkColDecs :: T.Text -> Either (String -> Q [Dec]) Type -> Q (Type, [Dec])
-- mkColDecs colNm colTy = do
--   let tablePrefix = ""
--   let rowTypeName = "toto"
--   let safeName = tablePrefix ++ (T.unpack . sanitizeTypeName $ colNm)
--   mColNm <- lookupTypeName safeName
--   case mColNm of
--     Just n -> pure (ConT n, []) -- Column's type was already defined
--     Nothing -> colDec (T.pack tablePrefix) rowTypeName colNm colTy


-- | Generate a column type.
-- recDecExplicit :: [(T.Text, Q Type)] -> Q Type
-- recDecExplicit = appT [t|Record|] . go
--   where go [] = return PromotedNilT
--         go ((n,t):cs) =
--           [t|($(litT $ strTyLit (T.unpack n)) :-> $t) ': $(go cs) |]

-- TODO pass on rowTypeName
-- myRowGen :: String -> [(T.Text, TsharkFieldDesc)] -> DecsQ
-- myRowGen rowName fields = do
--   rowType <- recDecExplicit tfields
--   -- let recTy = TySynD (mkName rowTypeName) [] (recDec colTypes)
--   let recTy = TySynD (mkName rowName) [] rowType
--   colDecs <- concat <$> mapM (uncurry $ colDecExplicit (T.pack tablePrefix)) headers
--   return [recTy]
--   where
--       tfields = map (\(colName, fullField) -> (colName, colType fullField)) fields
--

--myRow :: [(T.Text, TsharkFieldDesc)] -> RowGen a
--myRow fields = RowGen [] "" "|" "HostCols" []
--  where
--    --
--    tfields = map (\(colName, fullField) -> (colName, colType fullField)) fields

-- type CommonColumns = [Bool, Int, Double, T.Text]
-- rowGen :: FilePath -> RowGen CommonColumns

-- myColumnUniverse :: String -> FieldDescriptions -> Q [Dec]
-- myColumnUniverse rowTypeName fields = do
--     let colTys = map (\(_name, x) -> colType x) fields
--     colTypes <- tySynD (mkName rowTypeName) [] (promotedTypeList colTys)
--     -- colTypes <- sequenceQ colTys
--     -- f <- sequenceA (colTypes)
--     return [colTypes]
--     -- return $ tySynD colTys
--     -- where
--     --   colTypes :: Q Type


promotedTypeList :: [Q Type] -> Q Type
promotedTypeList []     = promotedNilT
promotedTypeList (t:ts) = [t| $promotedConsT $t $(promotedTypeList ts) |]

