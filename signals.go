/*-
 * Copyright 2015 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/csstaub/reloadable-tls"
)

// signalHandler. Listens for incoming SIGTERM or SIGUSR1 signals. If we get
// SIGTERM, stop listening for new connections and gracefully terminate the
// process. If we get SIGUSR1, reload certificates.
func signalHandler(proxy *proxy, reloadables []reloadable.Reloadable, closeables []io.Closer, context *Context) {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGTERM)
	defer signal.Stop(signals)

	for {
		// Wait for a signal
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGTERM:
				logger.Printf("received SIGTERM, shutting down")
				atomic.StoreInt32(&proxy.quit, 1)
				for _, closeable := range closeables {
					closeable.Close()
				}
				logger.Printf("done with signal handler")
				return

			case syscall.SIGUSR1:
				logger.Printf("received SIGUSR1, reloading certificates")
				context.status.Reloading()
				for _, reloadable := range reloadables {
					err := reloadable.Reload()
					if err != nil {
						logger.Printf("error reloading: %s", err)
					}
				}
				logger.Printf("reloading complete")
				context.status.Listening()
			}
		case _ = <-context.watcher:
			logger.Printf("reloading certificates (timer fired)")
			context.status.Reloading()
			for _, reloadable := range reloadables {
				err := reloadable.Reload()
				if err != nil {
					logger.Printf("error reloading: %s", err)
				}
			}
			logger.Printf("reloading complete")
			context.status.Listening()
		}
	}
}
