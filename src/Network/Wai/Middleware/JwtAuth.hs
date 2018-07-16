{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
module Network.Wai.Middleware.JwtAuth where

import Protolude
import Prelude (String, lookup)

import           Control.Monad.Except
import           Control.Monad.Trans.Class
import           Control.Monad.Trans.Except
import           Control.Monad.Trans.Maybe
import           Crypto.PubKey.ECC.Generate (generateQ)
import           Crypto.PubKey.ECC.Types
import           Crypto.PubKey.ECC.ECDSA (PublicKey(..), KeyPair(..))
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import           Data.Aeson
import           Data.Aeson.Types
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Maybe
import           Data.PEM
import           Data.X509 (PubKey(..), PrivKey(..), PubKeyEC(..), PrivKeyEC(..))
import           Data.X509.EC 
import           Jose.Jwa (Alg(Signed), JwsAlg(ES256))
import           Jose.Jwk
import qualified Jose.Jwt as JWT
import           Network.Wai
import           Network.HTTP.Types (hAuthorization)
import           Network.HTTP.Types.Status (status401)

jwtAuth :: [Jwk] -> Middleware
jwtAuth keys app req res = do
    checked <- runMaybeT $ do
        hdr <- liftMaybe $ lookup hAuthorization $ requestHeaders req
        unless (hdr `startsWith` "Bearer ") empty
        let token = (BS.drop 7 hdr)
        MaybeT $ rightToMaybe <$> JWT.decode keys Nothing token
    case checked of
        Nothing -> res $ responseLBS status401 [] "Invalid Bearer Token"
        Just x -> app req res
    where
        liftMaybe = MaybeT . return
        startsWith bs = flip BS.take bs . BS.length >>= (==)

loadPubKeys :: [FilePath] -> IO [Jwk]
loadPubKeys = fmap catMaybes . traverse loadPubKey

-- loadPrivKeys :: [FilePath] -> IO [Jwk]
-- loadPrivKeys = fmap catMaybes . traverse loadPrivKey

loadPubKey :: FilePath -> IO (Maybe Jwk)
loadPubKey = loadKey pub2jwk

-- loadPrivKey :: FilePath -> IO (Maybe Jwk)
-- loadPrivKey = loadKey priv2jwk

loadKey :: (PEM -> Either String Jwk) -> FilePath -> IO (Maybe Jwk)
loadKey convert path = do
    fileBytes <- BS.readFile path
    return . rightToMaybe $ do
        pem <- pemParseBS fileBytes >>= headErr "Empty PEM"
        convert pem

pub2jwk :: PEM -> Either String Jwk
pub2jwk pem = do
    asn1stream <- first show . decodeASN1' DER $ pemContent pem
    key <- fst <$> fromASN1 asn1stream
    pubKey <- case key of
        PubKeyEC ec -> Right ec
        _ -> Left "Invalid Key Type for JWT"
    case pubKey of
        PubKeyEC_Prime{..} -> Left "Unsupported Curve for JWT: Prime"
        PubKeyEC_Named{..} -> case pubkeyEC_name of
            SEC_p256r1 ->
                let curve = getCurveByName SEC_p256r1 
                    point = unserializePoint curve pubkeyEC_pub
                    jwkcrv = parseMaybe parseJSON $ String "P-256"
                in  case (point, jwkcrv) of
                    (Nothing, _) -> Left "Point is not on specified Curve"
                    (_, Nothing) -> Left "Could not parse curve"
                    (Just p, Just c) -> Right $ EcPublicJwk (PublicKey curve p) Nothing Nothing (Just $ Signed ES256) c
            c@_ -> Left $ "Unsupported Curve for JWT: " <> show c

-- priv2jwk :: PEM -> Either String Jwk
-- priv2jwk pem = do
--     asn1stream <- first show . decodeASN1' DER $ pemContent pem
--     key <- fst <$> fromASN1 asn1stream
--     privKey <- case key of
--         PrivKeyEC ec -> Right ec
--         _ -> Left "Invalid Key Type for JWT"
--     case privKey of
--         PrivKeyEC_Prime{..} -> Left "Unsupported Curve for JWT: Prime"
--         PrivKeyEC_Named{..} -> case privkeyEC_name of
--             SEC_p256r1 ->
--                 let curve = getCurveByName SEC_p256r1
--                     point = generateQ curve privkeyEC_priv
--                     jwkcrv = parseMaybe parseJSON $ String "P-256"
--                 in  case jwkcrv of
--                     Nothing -> "Could not parse curve"
--                     Just c -> Right $ EcPrivateJwk (KeyPair curve point privkeyEC_priv) Nothing Nothing (Just $ Signed ES256) c
--             c@_ -> Left $ "Unsupported Curve for JWT: " <> show c

headErr :: e -> [a] -> Either e a
headErr e = maybeToRight e . head