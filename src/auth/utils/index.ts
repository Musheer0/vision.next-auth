export function getFutureDate(days) {
  const result = new Date();
  result.setDate(result.getDate() + days);
  return result;
}
export function getFutureMinute(minutes) {
  const result = new Date();
  result.setMinutes(result.getMinutes() + minutes);
  return result;
}
