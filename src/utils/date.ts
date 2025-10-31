export function getExpiryDate(expiryString: string): Date {
  const unit = expiryString.slice(-1);
    const value = parseInt(expiryString.slice(0, -1), 10);
    const date = new Date();
    if (unit === 'd') {
        date.setDate(date.getDate() + value);
    } else if (unit === 'h') {
        date.setHours(date.getHours() + value);
    } else if (unit === 'm') {
        date.setMinutes(date.getMinutes() + value);
    }
    return date;
}