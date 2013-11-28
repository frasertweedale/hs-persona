-- This file is part of persona - Persona (BrowserID) library
-- Copyright (C) 2013  Fraser Tweedale
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

module Crypto.Persona
  (
    RelativeURI()
  , parseRelativeURI

  , SupportDocument(..)
  , Principal(..)
  , IdentityCertificate(..)
  ) where

import Prelude hiding (exp)

import Control.Applicative

import Data.Aeson
import Data.Aeson.Types
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import Network.URI

import Crypto.JOSE.Compact
import Crypto.JOSE.JWK
import Crypto.JWT


newtype RelativeURI = RelativeURI URI deriving (Eq, Show)

instance FromJSON RelativeURI where
  parseJSON = withText "URI" $
    maybe (fail "not a relative URI") pure . parseRelativeURI . T.unpack

instance ToJSON RelativeURI where
  toJSON (RelativeURI uri) = String $ T.pack $ show uri

parseRelativeURI :: String -> Maybe RelativeURI
parseRelativeURI = fmap RelativeURI . Network.URI.parseRelativeReference


data SupportDocument = SupportDocument
    { publicKey       :: JWK
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


-- TODO better email and domain name parsing
data Principal = EmailPrincipal T.Text | HostPrincipal T.Text

instance FromJSON Principal where
  parseJSON = withObject "Principal" (\o ->
    EmailPrincipal <$> o .: "email"
    <|> HostPrincipal <$> o .: "host")

instance ToJSON Principal where
  toJSON (EmailPrincipal s) = object ["email" .= s]
  toJSON (HostPrincipal s) = object ["host" .= s]


data IdentityCertificate = IdentityCertificate
  { certJWT :: JWT
  , certIss :: StringOrURI
  , certExp :: IntDate
  , certPub :: JWK
  , certPri :: Principal
  }

instance FromCompact IdentityCertificate where
  fromCompact xs = do
    jwt <- fromCompact xs
    iss <- maybe (Left "missing iss") Right $ claimIss $ jwtClaimsSet jwt
    exp <- maybe (Left "missing exp") Right $ claimExp $ jwtClaimsSet jwt
    pubValue <- maybe (Left "missing \"public-key\"") Right $
      M.lookup "public-key" $ unregisteredClaims $ jwtClaimsSet jwt
    pub <- parseEither parseJSON pubValue
    priValue <- maybe (Left "missing key \"principal\"") Right $
      M.lookup "principal" $ unregisteredClaims $ jwtClaimsSet jwt
    pri <- parseEither parseJSON priValue
    return $ IdentityCertificate jwt iss exp pub pri

instance ToCompact IdentityCertificate where
  toCompact (IdentityCertificate jwt _ _ _ _) = toCompact jwt
