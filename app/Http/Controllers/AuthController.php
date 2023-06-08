<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Response;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    public function register(Request $request){
        // Validate fields
        $fields = $request->validate([
            'name' => 'required|string',
            'email'=> 'required|string|unique:users,email',
            'password'=> 'required|string|confirmed'
        ]);

        // Create user
        $user = User::create([
            'name'=> $fields['name'],
            'email'=> $fields['email'],
            'password'=> bcrypt($fields['password'])
        ]);

        // Create token
        $token = $user->createToken('myapptoken')-> plainTextToken;

        $response = [
            'user'=> $user,
            'token'=> $token
        ];

        return response($response, 201);
    }

    // Login
    public function login(Request $request)
    {
        $fields = $request->validate([
            'email'=> 'required|string',
            'password'=> 'required|string'
        ]);

        // Check email
        $user = User::where('email', $fields['email'])->first();

        // Check password
        if(!$user || !Hash::check($fields['password'], $user->password)){
            return response([
                'message'=> 'Wrong credentials'
            ], 401);
        }

        // Create token
        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    // Logout
    public function logout(Request $request){
        auth()->user()->tokens()->delete();

        return response([
            'message'=> 'You are Logged out'
        ]);
    }
}
