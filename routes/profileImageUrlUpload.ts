/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { URL, domainToASCII } from 'node:url'
import { isIP } from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      
      // SSRF mitigation: allow-list hostnames
      const ALLOWED_IMAGE_HOSTS = [
        'images.example.com',
        'cdn.example.net'
        // Add allowed image hostnames here
      ]
      
      let parsedUrl: URL
      try {
        parsedUrl = new URL(url)
      } catch (e) {
        res.status(400).send('Invalid image URL')
        return
      }
      
      // Only allow http(s)
      const allowedProtocols = ['http:', 'https:']
      if (!allowedProtocols.includes(parsedUrl.protocol)) {
        res.status(400).send('Unsupported protocol in image URL')
        return
      }
      
      // Normalize hostname for punycode/unicode, force lowercase
      const normalizedHost = domainToASCII(parsedUrl.hostname).toLowerCase()
      // Disallow IP addresses as hostnames
      if (isIP(normalizedHost)) {
        res.status(400).send('IP addresses not allowed as image host')
        return
      }
      // Only allow if host is on allow-list (case-insensitive compare)
      if (!ALLOWED_IMAGE_HOSTS.map(h => domainToASCII(h).toLowerCase()).includes(normalizedHost)) {
        res.status(400).send('Unapproved image host')
        return
      }
      
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
