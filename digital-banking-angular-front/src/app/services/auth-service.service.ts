import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { jwtDecode } from 'jwt-decode';

@Injectable({
  providedIn: 'root',
})
export class AuthServiceService {
  isAuthenticated: boolean = false;
  roles: any;
  username: any;
  access_token: any;
  constructor(private http: HttpClient, private router: Router) {}
  public login(username: string, password: string) {
    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
    });

    // Set the request body as URL-encoded parameters
    const body = new HttpParams()
      .set('username', username)
      .set('password', password);

    // Send the POST request
    return this.http.post('http://localhost:8080/auth/login', body.toString(), {
      headers,
    });
  }
  public loadProfile(data: any) {
    this.isAuthenticated = true;
    let jwtToken = data['accessToken'];
    this.access_token = jwtToken;
    let decodedJwt: any = jwtDecode(this.access_token);
    this.username = decodedJwt.sub;
    this.roles = decodedJwt.scope;
    window.localStorage.setItem('jwt-token', this.access_token);
  }
  loadJwtTokenFromLocalStorage() {
    let token = window.localStorage.getItem('jwt-token');
    if (token) {
      this.loadProfile({ accessToken: token });

      this.router.navigateByUrl('/admin/customers');
    }
  }
  public logout() {
    this.isAuthenticated = false;
    this.access_token = undefined;
    this.username = undefined;
    this.roles = undefined;
    window.localStorage.removeItem('jwt-token');
    this.router.navigateByUrl('/login');
  }
}
