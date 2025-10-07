import passport from "passport";
import { Request } from "express";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as LocalStrategy } from "passport-local";

import { config } from "./app.config";
import { NotFoundException } from "../utils/appError";
import { ProviderEnum } from "../enums/account-provider.enum";
import {
  loginOrCreateAccountService,
  verifyUserService,
} from "../services/auth.service";

passport.use(
  new GoogleStrategy(
    {
      clientID: config.GOOGLE_CLIENT_ID,
      clientSecret: config.GOOGLE_CLIENT_SECRET,
      callbackURL: config.GOOGLE_CALLBACK_URL,
      scope: ["profile", "email"],
      passReqToCallback: true,
    },
    async (req: Request, accessToken, refreshToken, profile, done) => {
      try {
        const { email, sub: googleId, picture } = profile._json;
        console.log(profile, "profile");
        console.log(googleId, "googleId");
        if (!googleId) {
          throw new NotFoundException("Google ID (sub) is missing");
        }

        const { user } = await loginOrCreateAccountService({
          provider: ProviderEnum.GOOGLE,
          displayName: profile.displayName,
          providerId: googleId,
          picture: picture,
          email: email,
        });
        done(null, user);
      } catch (error) {
        done(error, false);
      }
    }
  )
);

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
      session: true,
    },
    async (email, password, done) => {
      try {
        const user = await verifyUserService({ email, password });
        return done(null, user);
      } catch (error: any) {
        return done(error, false, { message: error?.message });
      }
    }
  )
);

// passport.serializeUser((user: any, done) => done(null, user));


interface SessionUser {
  _id: string;
  name: string;
  email: string;
  profilePicture?: string | null;
  isActive: boolean;
  lastLogin: Date | null;
  createdAt: Date;
  updatedAt: Date;
  password?: string;
  currentWorkspaceId?: string;
}


passport.serializeUser((user: any, done) => {
  try {

    const userObject = user.toObject ? user.toObject() : user;


    const sessionUser: SessionUser = {
      _id: userObject._id.toString(), 
      name: userObject.name,
      email: userObject.email,
      profilePicture: userObject.profilePicture,
      isActive: userObject.isActive,
      lastLogin: userObject.lastLogin,
      createdAt: userObject.createdAt,
      updatedAt: userObject.updatedAt,
      password: userObject.password ? userObject.password : null,
      currentWorkspaceId: userObject.currentWorkspace ? userObject.currentWorkspace.toString() : undefined,
    };

    done(null, sessionUser);
  } catch (error) {
    console.error("Serialization Error:", error);
    done(error, false);
  }
});

passport.deserializeUser((user: any, done) => done(null, user));
