class ApiResponse{
    constructor(ststusCode,data,message="Success"){
        this.ststusCode=ststusCode
        this.data=data
        this.message=ststusCode<400
    }
}