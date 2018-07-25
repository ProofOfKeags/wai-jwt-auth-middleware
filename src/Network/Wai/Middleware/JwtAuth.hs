{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
module Network.Wai.Middleware.JwtAuth where

import Protolude
import Prelude (String, lookup)

import           Control.Monad.Trans.Maybe
import           Crypto.PubKey.ECC.Types
import           Crypto.PubKey.ECC.Generate
import           Crypto.PubKey.ECC.ECDSA (PublicKey(..), KeyPair(..))
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types

-- import           Data.X509.Internal
-- import           Data.X509.OID
-- import           Data.X509.AlgorithmIdentifier

import           Data.Aeson
import           Data.Aeson.Types
import qualified Data.ByteString as BS
import qualified Data.HashMap.Lazy as HM
import           Data.PEM
import qualified Data.Vault.Lazy as V
import           Data.X509 (PubKey(..), PubKeyEC(..), PrivKeyEC(..), PrivKey(..))
import           Data.X509.EC 
import           Data.X509.Memory 
import           Jose.Jwa (Alg(Signed), JwsAlg(ES256))
import           Jose.Jwk
import qualified Jose.Jwt as JWT
import           Network.Wai
import           Network.HTTP.Types (hAuthorization)
import           Network.HTTP.Types.Status (status401)

type IssuerMap = HM.HashMap Text Jwk

jwtAuthMap :: V.Key Value -> IssuerMap -> Middleware
jwtAuthMap = jwtAuth' f
    where f m bs = maybeToList $ do
            claims <- rightToMaybe $ JWT.decodeClaims bs
            iss <- JWT.jwtIss $ snd claims
            HM.lookup iss m

jwtAuthList :: V.Key Value -> [Jwk] -> Middleware
jwtAuthList = jwtAuth' const

jwtAuthSingle :: V.Key Value -> Jwk -> Middleware
jwtAuthSingle = jwtAuth' (return .* const)
    where (.*) = (.).(.)

jwtAuth' :: (a -> ByteString -> [Jwk]) -> V.Key Value -> a -> Middleware
jwtAuth' keyFn attr keyStore app req res = do
    checked <- runMaybeT $ do
        hdr <- liftMaybe $ lookup hAuthorization $ requestHeaders req
        unless (hdr `startsWith` "Bearer ") empty
        let token = (BS.drop 7 hdr)
        let keys = keyFn keyStore token
        MaybeT $ rightToMaybe <$> JWT.decode keys Nothing token
    case checked of
        Nothing -> res $ responseLBS status401 [] "Invalid Bearer Token"
        Just x -> case x of
            JWT.Unsecured b -> app (attach b req) res
            JWT.Jws (_, b) -> app (attach b req) res
            JWT.Jwe (_, b) -> app (attach b req) res
    where
        attach b r = case decodeStrict b of
            Nothing -> r
            Just v -> let vault' = V.insert attr v (vault r)
                      in r { vault = vault' }
        liftMaybe = MaybeT . return
        startsWith bs = flip BS.take bs . BS.length >>= (==)

loadPubKeys :: [FilePath] -> IO [Jwk]
loadPubKeys = fmap catMaybes . traverse loadPubKey

loadPubKey :: FilePath -> IO (Maybe Jwk)
loadPubKey = loadKey pub2jwk

--loadPubKey :: FilePath -> IO (Maybe Jwk)
--loadPubKey = loadKey pub2jwk

--priv2jwk :: PEM -> IO()
--priv2jwk pem = print (first show . decodeASN1' DER $ pemContent pem)
----
-- loadKeyDev :: FilePath -> IO (Maybe [ASN1])
-- loadKeyDev path = do
--    fileBytes <- BS.readFile path
--    return . rightToMaybe $ do
--         pem <- pemParseBS fileBytes >>= headErr "Empty PEM"
--         asn1stream <- first show . decodeASN1' DER $ pemContent pem
--         return asn1stream

loadKey convert path = do
   fileBytes <- BS.readFile path
   return . rightToMaybe $ do
        pem <- pemParseBS fileBytes >>= headErr "Empty PEM"
        convert pem

--loadKey :: (PEM -> Either String Jwk) -> FilePath -> IO (Maybe Jwk)
--loadKey convert path = do
--    fileBytes <- BS.readFile path
--    pem <- pemParseBS fileBytes >>= headErr "Empty PEM"
--    convert pem

-- instance ASN1Object PrivKeyEC where
--     fromASN1 (Start Sequence
--         :IntVal 1
--         :OctetString privKey
--         :Start (Container Context 0)
--         :OID curveOid
--         :End (Container Context 0):xs) = case lookupByOID curvesOIDTable curveOid of
--             Just curveName -> Right (PrivKeyEC_Named curveName (privKey), xs)
--             Nothing        -> Left ("fromASN1: X509.Pubkey: EC unknown curve " ++ show curveOid)
--     fromASN1 l = Left ("fromASN1: X509.PrivKey: unknown format:" ++ show l)

priv2jwk :: PEM -> Either String Jwk
priv2jwk pem = do
    priv <- (headErr "No private keys in pem") . readKeyFileFromMemory . pemContent $ pem
    pp <- case priv of
            PrivKeyEC (PrivKeyEC_Named SEC_p256r1 privNumber) -> Right $ pair2jwk ((parseMaybe parseJSON $ String "P-256")) (privInt2ECPair (getCurveByName SEC_p256r1) privNumber)
            _ -> Left "Not an elliptic curve private key"
    return $ pp



privInt2ECPair :: Curve -> Integer -> KeyPair
privInt2ECPair c privNumber = KeyPair c (generateQ c privNumber) privNumber

pair2jwk :: Curve -> KeyPair -> Jwk
pair2jwk c p = EcPrivateJwk p Nothing Nothing Nothing c

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

headErr :: e -> [a] -> Either e a
headErr e = maybeToRight e . head