-- This file is part of persona - Persona (BrowserID) library
-- Copyright (C) 2013, 2014, 2015, 2016  Fraser Tweedale
--
-- persona is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

{-|

Mozilla Persona (formerly BrowserID) types.

-}
module Crypto.Persona
  (
    RelativeURI()
  , parseRelativeURI

  , DelegatedSupportDocument(DelegatedSupportDocument)
  , authority

  , SupportDocument
  , publicKey
  , authentication
  , provisioning
  , supportDocument

  , Principal(..)

  , certify

  , provisioningApiJsUrl
  , authenticationApiJsUrl
  ) where

import Prelude hiding (exp)

import Control.Applicative

import Control.Lens hiding (iat, (.=))
import Data.Aeson
import Data.Default.Class (def)
import qualified Data.Text as T
import Data.Time
import Data.Time.Clock.POSIX
import Network.URI (URI, parseRelativeReference)

import Crypto.JOSE
import Crypto.JOSE.Legacy
import Crypto.JWT


-- | Newtype of URI resticted to relative URIs.
--
newtype RelativeURI = RelativeURI URI deriving (Eq)

instance Show RelativeURI where
  show (RelativeURI uri) = show uri

instance FromJSON RelativeURI where
  parseJSON = withText "URI" $
    maybe (fail "not a relative URI") pure . parseRelativeURI . T.unpack

instance ToJSON RelativeURI where
  toJSON (RelativeURI uri) = String $ T.pack $ show uri

-- | Construct a 'RelativeURI'
--
parseRelativeURI :: String -> Maybe RelativeURI
parseRelativeURI = fmap RelativeURI . Network.URI.parseRelativeReference


-- | Basic /support document/.
--
-- See <https://developer.mozilla.org/en-US/Persona/.well-known-browserid>.
--
data SupportDocument = SupportDocument
    { _publicKey       :: JWK'
    , _authentication  :: RelativeURI
    , _provisioning    :: RelativeURI
    }
makeLenses ''SupportDocument

instance FromJSON SupportDocument where
  parseJSON = withObject "SupportDocument" (\o -> SupportDocument
    <$> o .: "public-key"
    <*> o .: "authentication"
    <*> o .: "provisioning")

instance ToJSON SupportDocument where
  toJSON (SupportDocument k a p) = object
    [ "public-key" .= k
    , "authentication" .= a
    , "provisioning" .= p
    ]

-- | Construct a 'SupportDocument'
--
-- The smart constructor is needed to ensure that any private key
-- material is stripped from the key.  Although RSA keys always have
-- public material the result is a 'Maybe SupportDocument' to enable
-- a move to the JSON Web Key (JWK) format.
--
supportDocument :: JWK' -> RelativeURI -> RelativeURI -> Maybe SupportDocument
supportDocument k a p =
  SupportDocument k a p & publicKey (preview asPublicKey)


-- | /Delegated support document/
--
newtype DelegatedSupportDocument = DelegatedSupportDocument
  { _authority :: String
  } deriving (Eq, Show)
makeLenses ''DelegatedSupportDocument

instance FromJSON DelegatedSupportDocument where
  parseJSON = withObject "DelegatedSupportDocument" $ \o ->
    DelegatedSupportDocument <$> o .: "authority"

instance ToJSON DelegatedSupportDocument where
  toJSON (DelegatedSupportDocument s) = object [ "authority" .= s ]


-- | Persona identity principal
--
-- TODO: actually restrict to email addresses or hostnames.
--
data Principal = EmailPrincipal T.Text | HostPrincipal T.Text

instance FromJSON Principal where
  parseJSON = withObject "Principal" (\o ->
    EmailPrincipal <$> o .: "email"
    <|> HostPrincipal <$> o .: "host")

instance ToJSON Principal where
  toJSON (EmailPrincipal s) = object ["email" .= s]
  toJSON (HostPrincipal s) = object ["host" .= s]


-- | Create an identity assertion.
--
certify
  :: MonadRandom m
  => JWK'         -- ^ Signing key
  -> StringOrURI  -- ^ Issuer
  -> UTCTime
  -- ^ Current time.  Will be used for the "iat" claim and in the
  -- calculation of the "exp" claim.
  -> Integer
  -- ^ Requested duration.  Will be used in the calculation of the
  -- "exp" claim.
  -> Value        -- ^ User public key object
  -> Principal    -- ^ Principal
  -> m (Either Error JWT)
certify k iss t dur pk principal =
  createJWSJWT (toJWK k) header claims
  where
  claims = emptyClaimsSet
    & claimIss .~ Just iss
    & claimExp .~ Just exp
    & claimIat .~ Just iat
    & addClaim "public-key" (toJSON pk)
    & addClaim "principal" (toJSON principal)
  header = def { headerAlg = Just RS256 }
  -- SHOULD NOT issue cert valid longer than duration
  -- MUST NOT issue cert valid longer than 24 hours
  exp = toMs $ addUTCTime (fromRational $ toRational $ min dur 86400) t
  iat = toMs t
  toMs = NumericDate . posixSecondsToUTCTime . (* 1000) . utcTimeToPOSIXSeconds


-- | URI to official provisioning JavaScript.
--
provisioningApiJsUrl :: String
provisioningApiJsUrl = "https://login.persona.org/provisioning_api.js"

-- | URI to official authentication JavaScript.
--
authenticationApiJsUrl :: String
authenticationApiJsUrl = "https://login.persona.org/provisioning_api.js"
