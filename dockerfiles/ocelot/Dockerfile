FROM microsoft/aspnetcore
FROM microsoft/dotnet
COPY . /gateway
WORKDIR /gateway
EXPOSE 1000
CMD ["dotnet","ApiGateway.dll"]