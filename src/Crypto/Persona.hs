-- This file is part of persona - Persona (BrowserID) library
-- Copyright (C) 2013, 2014  Fraser Tweedale
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

{-|

Mozilla Persona (formerly BrowserID) types.

-}
module Crypto.Persona
  (
    RelativeURI()
  , parseRelativeURI

  , SupportDocument(..)
  , Principal(..)
  , IdentityCertificate(..)

  , provisioningApiJsUrl
  , authenticationApiJsUrl
  ) where

import Prelude hiding (exp)

import Control.Applicative

import Data.Aeson
import Data.Aeson.Types
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import Network.URI

import Crypto.JOSE
import Crypto.JOSE.Legacy
import Crypto.JWT


-- | Newtype of URI resticted to relative URIs.
--
newtype RelativeURI = RelativeURI URI deriving (Eq, Show)

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
-- See https://developer.mozilla.org/en-US/Persona/.well-known-browserid.
--
data SupportDocument = SupportDocument
    { publicKey       :: JWK'
    , authentication  :: RelativeURI
    , provisioning    :: RelativeURI
    }

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


-- | Identity Certificate.
--
-- See https://github.com/mozilla/id-specs/blob/prod/browserid/index.md#identity-certificate.
--
data IdentityCertificate = IdentityCertificate
  { certJWT :: JWT
  , certIss :: StringOrURI
  , certExp :: NumericDate
  , certPub :: JWK'
  , certPri :: Principal
  }

instance FromCompact IdentityCertificate where
  fromCompact xs = do
    jwt <- fromCompact xs
    iss <- maybe (Left $ JSONDecodeError "missing iss") Right $
      claimIss $ jwtClaimsSet jwt
    exp <- maybe (Left $ JSONDecodeError "missing exp") Right $
      claimExp $ jwtClaimsSet jwt
    pubValue <- maybe (Left $ JSONDecodeError "missing \"public-key\"") Right $
      M.lookup "public-key" $ unregisteredClaims $ jwtClaimsSet jwt
    pub <- either (Left . JSONDecodeError) Right $
      parseEither parseJSON pubValue
    priValue <- maybe (Left $ JSONDecodeError "missing \"principal\"") Right $
      M.lookup "principal" $ unregisteredClaims $ jwtClaimsSet jwt
    pri <- either (Left . JSONDecodeError) Right $
      parseEither parseJSON priValue
    return $ IdentityCertificate jwt iss exp pub pri

instance ToCompact IdentityCertificate where
  toCompact (IdentityCertificate jwt _ _ _ _) = toCompact jwt


-- | URI to official provisioning JavaScript.
--
provisioningApiJsUrl :: String
provisioningApiJsUrl = "https://login.persona.org/provisioning_api.js"

-- | URI to official authentication JavaScript.
--
authenticationApiJsUrl :: String
authenticationApiJsUrl = "https://login.persona.org/provisioning_api.js"
