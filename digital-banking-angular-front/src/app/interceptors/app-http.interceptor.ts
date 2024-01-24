import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
} from '@angular/common/http';
import { Observable, catchError, throwError } from 'rxjs';
import { AuthServiceService } from '../services/auth-service.service';

@Injectable()
export class AppHttpInterceptor implements HttpInterceptor {
  constructor(private authService: AuthServiceService) {}

  intercept(
    request: HttpRequest<unknown>,
    next: HttpHandler
  ): Observable<HttpEvent<unknown>> {
    if (!request.url.includes('/auth/login')) {
      let newRequest = request.clone({
        headers: request.headers.set(
          'Authorization',
          'Bearer ' + this.authService.access_token
        ),
      });

      return next.handle(newRequest).pipe(
        catchError((err) => {
          if (err.status == 401) {
            this.authService.logout();
          }
          return throwError(err.message);
        })
      );
    } else return next.handle(request);
  }
}
